package tmux

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Debug flag - set via environment variable AGENTDECK_DEBUG=1
var debugStatusEnabled = os.Getenv("AGENTDECK_DEBUG") == "1"

func debugLog(format string, args ...interface{}) {
	if debugStatusEnabled {
		log.Printf("[STATUS] "+format, args...)
	}
}

const SessionPrefix = "agentdeck_"

// IsTmuxAvailable checks if tmux is installed and accessible
// Returns nil if tmux is available, otherwise returns an error with details
func IsTmuxAvailable() error {
	cmd := exec.Command("tmux", "-V")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tmux not found or not working: %w (output: %s)", err, string(output))
	}
	return nil
}

// Tool detection patterns (used by DetectTool for initial tool identification)
var toolDetectionPatterns = map[string][]*regexp.Regexp{
	"claude": {
		regexp.MustCompile(`(?i)claude`),
		regexp.MustCompile(`(?i)anthropic`),
	},
	"gemini": {
		regexp.MustCompile(`(?i)gemini`),
		regexp.MustCompile(`(?i)google ai`),
	},
	"aider": {
		regexp.MustCompile(`(?i)aider`),
	},
	"codex": {
		regexp.MustCompile(`(?i)codex`),
		regexp.MustCompile(`(?i)openai`),
	},
}

// StateTracker tracks content changes for notification-style status detection
//
// StateTracker implements a simple 3-state model:
//
//	GREEN (active)   = Content changed within 2 seconds
//	YELLOW (waiting) = Content stable, user hasn't seen it
//	GRAY (idle)      = Content stable, user has seen it
type StateTracker struct {
	lastHash       string    // SHA256 of normalized content
	lastChangeTime time.Time // When content last changed
	acknowledged   bool      // User has seen this state (yellow vs gray)
}

// activityCooldown is how long to show GREEN after content stops changing.
// This prevents flickering during natural micro-pauses in AI output.
// - 2 seconds: Covers most pauses between output bursts
// - 3 seconds: More conservative, fewer false yellows
const activityCooldown = 2 * time.Second

// Session represents a tmux session
// NOTE: All mutable fields are protected by mu. The Bubble Tea event loop is single-threaded,
// but we use mutex protection for defensive programming and future-proofing.
type Session struct {
	Name        string
	DisplayName string
	WorkDir     string
	Command     string
	Created     time.Time

	// mu protects all mutable fields below from concurrent access
	mu sync.Mutex

	// Content tracking for HasUpdated (separate from StateTracker)
	lastHash    string
	lastContent string

	// Cached tool detection (avoids re-detecting every status check)
	detectedTool     string
	toolDetectedAt   time.Time
	toolDetectExpiry time.Duration // How long before re-detecting (default 30s)

	// Simple state tracking (hash-based)
	stateTracker *StateTracker

	// Last status returned (for debugging)
	lastStableStatus string
}

// ensureStateTrackerLocked lazily allocates the tracker so callers can safely
// acknowledge even before the first GetStatus call.
// MUST be called with mu held.
func (s *Session) ensureStateTrackerLocked() {
	if s.stateTracker == nil {
		s.stateTracker = &StateTracker{
			lastHash:       "",
			lastChangeTime: time.Now().Add(-activityCooldown),
			acknowledged:   false,
		}
	}
}

// NewSession creates a new Session instance with a unique name
func NewSession(name, workDir string) *Session {
	sanitized := sanitizeName(name)
	// Add unique suffix to prevent name collisions
	uniqueSuffix := generateShortID()
	return &Session{
		Name:             SessionPrefix + sanitized + "_" + uniqueSuffix,
		DisplayName:      name,
		WorkDir:          workDir,
		Created:          time.Now(),
		lastStableStatus: "waiting",
		toolDetectExpiry: 30 * time.Second, // Re-detect tool every 30 seconds
		// stateTracker and promptDetector will be created lazily on first status check
	}
}

// ReconnectSession creates a Session object for an existing tmux session
// This is used when loading sessions from storage - it properly initializes
// all fields needed for status detection to work correctly
func ReconnectSession(tmuxName, displayName, workDir, command string) *Session {
	return &Session{
		Name:             tmuxName,
		DisplayName:      displayName,
		WorkDir:          workDir,
		Command:          command,
		Created:          time.Now(), // Approximate - we don't persist this
		lastStableStatus: "waiting",
		toolDetectExpiry: 30 * time.Second,
		// stateTracker and promptDetector will be created lazily on first status check
	}
}

// ReconnectSessionWithStatus creates a Session with pre-initialized state based on previous status
// This restores the exact status state across app restarts:
//   - "idle" (gray): acknowledged=true, cooldown expired
//   - "waiting" (yellow): acknowledged=false, cooldown expired
//   - "active" (green): will be recalculated based on actual content changes
func ReconnectSessionWithStatus(tmuxName, displayName, workDir, command string, previousStatus string) *Session {
	sess := ReconnectSession(tmuxName, displayName, workDir, command)

	switch previousStatus {
	case "idle":
		// Session was acknowledged (user saw it) - restore as GRAY
		sess.stateTracker = &StateTracker{
			lastHash:       "",                                // Will be set on first GetStatus
			lastChangeTime: time.Now().Add(-10 * time.Second), // Cooldown expired
			acknowledged:   true,
		}
		sess.lastStableStatus = "idle"

	case "waiting", "active":
		// Session needs attention - restore as YELLOW
		// Active sessions will show green when content changes
		sess.stateTracker = &StateTracker{
			lastHash:       "",                                // Will be set on first GetStatus
			lastChangeTime: time.Now().Add(-10 * time.Second), // Cooldown expired
			acknowledged:   false,
		}
		sess.lastStableStatus = "waiting"

	default:
		// Unknown status - default to waiting
		sess.lastStableStatus = "waiting"
	}

	return sess
}

// generateShortID generates a short random ID for uniqueness
func generateShortID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp
		return fmt.Sprintf("%d", time.Now().UnixNano()%100000)
	}
	return hex.EncodeToString(b)
}

// sanitizeName converts a display name to a valid tmux session name
func sanitizeName(name string) string {
	// Replace spaces and special characters with hyphens
	re := regexp.MustCompile(`[^a-zA-Z0-9-]+`)
	return re.ReplaceAllString(name, "-")
}

// Start creates and starts a tmux session
func (s *Session) Start(command string) error {
	s.Command = command

	// Check if session already exists (shouldn't happen with unique IDs, but handle gracefully)
	if s.Exists() {
		// Session with this exact name exists - regenerate with new unique suffix
		sanitized := sanitizeName(s.DisplayName)
		s.Name = SessionPrefix + sanitized + "_" + generateShortID()
	}

	// Ensure working directory exists
	workDir := s.WorkDir
	if workDir == "" {
		workDir = os.Getenv("HOME")
	}

	// Create new tmux session in detached mode
	cmd := exec.Command("tmux", "new-session", "-d", "-s", s.Name, "-c", workDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create tmux session: %w (output: %s)", err, string(output))
	}

	// Set default window/pane styles to prevent color issues in some terminals (Warp, etc.)
	// This ensures no unexpected background colors are applied
	_ = exec.Command("tmux", "set-option", "-t", s.Name, "window-style", "default").Run()
	_ = exec.Command("tmux", "set-option", "-t", s.Name, "window-active-style", "default").Run()

	// Enable mouse mode for proper scrolling (per-session, doesn't affect user's other sessions)
	// This allows:
	// - Mouse wheel scrolling through terminal history
	// - Text selection with mouse
	// - Pane resizing with mouse
	// Non-fatal: session still works, just without mouse support
	// This can fail on very old tmux versions
	_ = exec.Command("tmux", "set-option", "-t", s.Name, "mouse", "on").Run()

	// Send the command to the session
	if command != "" {
		if err := s.SendKeys(command); err != nil {
			return fmt.Errorf("failed to send command: %w", err)
		}
		if err := s.SendEnter(); err != nil {
			return fmt.Errorf("failed to send enter: %w", err)
		}
	}

	return nil
}

// Exists checks if the tmux session exists
func (s *Session) Exists() bool {
	cmd := exec.Command("tmux", "has-session", "-t", s.Name)
	return cmd.Run() == nil
}

// EnableMouseMode enables mouse scrolling, clipboard integration, and optimal settings
// Safe to call multiple times - just sets the options again
//
// Enables:
// - mouse on: Mouse wheel scrolling, text selection, pane resizing
// - set-clipboard on: OSC 52 clipboard integration (works with modern terminals)
// - history-limit 50000: Large scrollback buffer for AI agent output
//
// Note: With mouse mode on, hold Shift while selecting to use native terminal selection
// instead of tmux's selection (useful for copying to system clipboard in some terminals)
func (s *Session) EnableMouseMode() error {
	// Enable mouse support
	mouseCmd := exec.Command("tmux", "set-option", "-t", s.Name, "mouse", "on")
	if err := mouseCmd.Run(); err != nil {
		return err
	}

	// Enable OSC 52 clipboard integration
	// This allows tmux to copy directly to system clipboard in supported terminals
	// (iTerm2, Alacritty, kitty, Windows Terminal, etc.)
	clipboardCmd := exec.Command("tmux", "set-option", "-t", s.Name, "set-clipboard", "on")
	if err := clipboardCmd.Run(); err != nil {
		// Non-fatal: older tmux versions may not support this
		debugLog("%s: failed to enable clipboard: %v", s.DisplayName, err)
	}

	// Set large history limit for AI agent sessions (default is 2000)
	// AI agents produce a lot of output, so we need more scrollback
	historyCmd := exec.Command("tmux", "set-option", "-t", s.Name, "history-limit", "50000")
	if err := historyCmd.Run(); err != nil {
		// Non-fatal: history limit is a nice-to-have
		debugLog("%s: failed to set history-limit: %v", s.DisplayName, err)
	}

	return nil
}

// Kill terminates the tmux session
func (s *Session) Kill() error {
	cmd := exec.Command("tmux", "kill-session", "-t", s.Name)
	return cmd.Run()
}

// CapturePane captures the visible pane content
func (s *Session) CapturePane() (string, error) {
	// -J joins wrapped lines and trims trailing spaces so hashes don't change on resize
	cmd := exec.Command("tmux", "capture-pane", "-t", s.Name, "-p", "-J")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to capture pane: %w", err)
	}
	return string(output), nil
}

// CaptureFullHistory captures the scrollback history (limited to last 2000 lines for performance)
func (s *Session) CaptureFullHistory() (string, error) {
	// Limit to last 2000 lines to balance content availability with memory usage
	// AI agent conversations can be long - 2000 lines captures ~40-80 screens of content
	// -J joins wrapped lines and trims trailing spaces so hashes don't change on resize
	cmd := exec.Command("tmux", "capture-pane", "-t", s.Name, "-p", "-J", "-S", "-2000")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to capture history: %w", err)
	}
	return string(output), nil
}

// HasUpdated checks if the pane content has changed since last check
func (s *Session) HasUpdated() (bool, error) {
	content, err := s.CapturePane()
	if err != nil {
		return false, err
	}

	// Calculate SHA256 hash of content
	hash := sha256.Sum256([]byte(content))
	hashStr := hex.EncodeToString(hash[:])

	// Protect access to lastHash and lastContent
	s.mu.Lock()
	defer s.mu.Unlock()

	// First time check
	if s.lastHash == "" {
		s.lastHash = hashStr
		s.lastContent = content
		return true, nil
	}

	// Compare with previous hash
	if hashStr != s.lastHash {
		s.lastHash = hashStr
		s.lastContent = content
		return true, nil
	}

	return false, nil
}

// DetectTool detects which AI coding tool is running in the session
// Uses caching to avoid re-detection on every call
func (s *Session) DetectTool() string {
	// Check cache first (read lock pattern for better concurrency)
	s.mu.Lock()
	if s.detectedTool != "" && time.Since(s.toolDetectedAt) < s.toolDetectExpiry {
		result := s.detectedTool
		s.mu.Unlock()
		return result
	}
	s.mu.Unlock()

	// Detect tool from command first (most reliable)
	if s.Command != "" {
		cmdLower := strings.ToLower(s.Command)
		var tool string
		if strings.Contains(cmdLower, "claude") {
			tool = "claude"
		} else if strings.Contains(cmdLower, "gemini") {
			tool = "gemini"
		} else if strings.Contains(cmdLower, "aider") {
			tool = "aider"
		} else if strings.Contains(cmdLower, "codex") {
			tool = "codex"
		}
		if tool != "" {
			s.mu.Lock()
			s.detectedTool = tool
			s.toolDetectedAt = time.Now()
			s.mu.Unlock()
			return tool
		}
	}

	// Fallback to content detection
	content, err := s.CapturePane()
	if err != nil {
		s.mu.Lock()
		s.detectedTool = "shell"
		s.toolDetectedAt = time.Now()
		s.mu.Unlock()
		return "shell"
	}

	// Strip ANSI codes for accurate matching
	cleanContent := StripANSI(content)

	// Check using pre-compiled patterns
	detectedTool := "shell"
	for tool, patterns := range toolDetectionPatterns {
		for _, pattern := range patterns {
			if pattern.MatchString(cleanContent) {
				detectedTool = tool
				break
			}
		}
		if detectedTool != "shell" {
			break
		}
	}

	s.mu.Lock()
	s.detectedTool = detectedTool
	s.toolDetectedAt = time.Now()
	s.mu.Unlock()
	return detectedTool
}

// ForceDetectTool forces a re-detection of the tool, ignoring cache
func (s *Session) ForceDetectTool() string {
	s.mu.Lock()
	s.detectedTool = ""
	s.toolDetectedAt = time.Time{}
	s.mu.Unlock()
	return s.DetectTool()
}

// AcknowledgeWithSnapshot marks the session as seen and baselines the current
// content hash. Called when user detaches from session.
func (s *Session) AcknowledgeWithSnapshot() {
	shortName := s.DisplayName
	if len(shortName) > 12 {
		shortName = shortName[:12]
	}

	// Capture content before acquiring lock (CapturePane is slow)
	var content string
	var captureErr error
	exists := s.Exists()
	if exists {
		content, captureErr = s.CapturePane()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.ensureStateTrackerLocked()

	if !exists {
		s.stateTracker.acknowledged = true
		s.lastStableStatus = "inactive"
		debugLog("%s: AckSnapshot session gone → inactive", shortName)
		return
	}

	if captureErr != nil {
		s.stateTracker.acknowledged = true
		s.lastStableStatus = "idle"
		debugLog("%s: AckSnapshot capture error → idle", shortName)
		return
	}

	// Snapshot current content so next poll doesn't trigger "active"
	cleanContent := s.normalizeContent(content)
	newHash := s.hashContent(cleanContent)
	prevHash := s.stateTracker.lastHash
	s.stateTracker.lastHash = newHash
	s.stateTracker.acknowledged = true
	s.lastStableStatus = "idle"
	prevHashShort := "(empty)"
	if len(prevHash) >= 16 {
		prevHashShort = prevHash[:16]
	}
	debugLog("%s: AckSnapshot hash %s → %s, ack=true → idle", shortName, prevHashShort, newHash[:16])
}

// GetStatus returns the current status of the session
//
// Time-based 3-state model to prevent flickering:
//
//	GREEN (active)   = Content changed within activityCooldown (2 seconds)
//	YELLOW (waiting) = Cooldown expired + NOT acknowledged (needs attention)
//	GRAY (idle)      = Cooldown expired + acknowledged (user has seen it)
//
// Key insight: AI agents output in bursts with micro-pauses. A time-based
// cooldown prevents flickering during these natural pauses - we stay GREEN
// for 2 seconds after ANY content change, regardless of micro-pauses.
//
// Logic:
// 1. Capture content and hash it
// 2. If hash changed → update lastChangeTime, return GREEN
// 3. If hash same → check if cooldown expired
//   - If within cooldown → GREEN (still considered active)
//   - If cooldown expired → YELLOW or GRAY based on acknowledged
func (s *Session) GetStatus() (string, error) {
	shortName := s.DisplayName
	if len(shortName) > 12 {
		shortName = shortName[:12]
	}

	// Perform expensive operations before acquiring lock
	if !s.Exists() {
		s.mu.Lock()
		s.lastStableStatus = "inactive"
		s.mu.Unlock()
		debugLog("%s: session doesn't exist → inactive", shortName)
		return "inactive", nil
	}

	// Capture current content (slow operation - do before lock)
	content, err := s.CapturePane()
	if err != nil {
		s.mu.Lock()
		s.lastStableStatus = "inactive"
		s.mu.Unlock()
		debugLog("%s: capture error → inactive", shortName)
		return "inactive", nil
	}

	// === BUSY INDICATOR CHECK (before hash comparison) ===
	// If Claude shows "esc to interrupt", spinners, or "Thinking..." - it's actively working
	// This catches cases where normalized content hash doesn't change
	// (e.g., "Thinking... (40s)" → "Thinking... (41s)" both normalize to same hash)
	if s.hasBusyIndicator(content) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.ensureStateTrackerLocked()
		s.stateTracker.lastChangeTime = time.Now() // Reset cooldown
		s.stateTracker.acknowledged = false
		s.lastStableStatus = "active"
		debugLog("%s: BUSY INDICATOR → active", shortName)
		return "active", nil
	}

	// Clean content: strip ANSI codes, spinner characters, normalize whitespace
	cleanContent := s.normalizeContent(content)
	currentHash := s.hashContent(cleanContent)

	// Handle empty content - use placeholder hash to avoid edge cases
	if currentHash == "" || cleanContent == "" {
		currentHash = "__empty__"
	}

	// Now acquire lock for state manipulation
	s.mu.Lock()
	defer s.mu.Unlock()

	// Initialize state tracker on first call
	// === SIMPLIFIED STATUS LOGIC ===
	// 0. Busy indicator present → return "active" (GREEN) - handled above
	// 1. New session (nil tracker) → init, return "idle" (GRAY) - no yellow flash
	// 2. Restored session (empty hash) → set hash, return "idle" (GRAY) - no yellow flash
	// 3. Content changed → return "active" (GREEN)
	// 4. Content same, within cooldown → return "active" (GREEN)
	// 5. Content same, cooldown expired → return based on acknowledged

	// New session - first poll: start as IDLE (gray) to avoid yellow flash
	// Busy indicator check above will catch actively running sessions
	if s.stateTracker == nil {
		s.stateTracker = &StateTracker{
			lastHash:       currentHash,
			lastChangeTime: time.Now().Add(-activityCooldown), // Pre-expired
			acknowledged:   true,                              // Start idle (gray)
		}
		s.lastStableStatus = "idle"
		debugLog("%s: INIT → idle (no flash)", shortName)
		return "idle", nil
	}

	// Restored session - set baseline hash, respect saved acknowledged state
	// Busy indicator check above already catches actively running sessions
	if s.stateTracker.lastHash == "" {
		s.stateTracker.lastHash = currentHash
		// Don't change acknowledged - respect value from ReconnectSessionWithStatus
		if s.stateTracker.acknowledged {
			s.lastStableStatus = "idle"
			debugLog("%s: RESTORED ack=true → idle", shortName)
			return "idle", nil
		}
		s.lastStableStatus = "waiting"
		debugLog("%s: RESTORED ack=false → waiting", shortName)
		return "waiting", nil
	}

	// Content changed → GREEN
	if s.stateTracker.lastHash != currentHash {
		s.stateTracker.lastHash = currentHash
		s.stateTracker.lastChangeTime = time.Now()
		s.stateTracker.acknowledged = false
		s.lastStableStatus = "active"
		debugLog("%s: CHANGED → active", shortName)
		return "active", nil
	}

	// Content same - check cooldown
	if time.Since(s.stateTracker.lastChangeTime) < activityCooldown {
		s.lastStableStatus = "active"
		debugLog("%s: COOLDOWN → active", shortName)
		return "active", nil
	}

	// Cooldown expired → YELLOW or GRAY
	if s.stateTracker.acknowledged {
		s.lastStableStatus = "idle"
		debugLog("%s: IDLE → idle", shortName)
		return "idle", nil
	}
	s.lastStableStatus = "waiting"
	debugLog("%s: WAITING → waiting", shortName)
	return "waiting", nil
}

// Acknowledge marks the session as "seen" by the user
// Call this when user attaches to the session
func (s *Session) Acknowledge() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ensureStateTrackerLocked()
	s.stateTracker.acknowledged = true
	s.lastStableStatus = "idle"
}

// ResetAcknowledged marks the session as needing attention
// Call this when a hook event indicates the agent finished (Stop, AfterAgent)
// This ensures the session shows yellow (waiting) instead of gray (idle)
func (s *Session) ResetAcknowledged() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ensureStateTrackerLocked()
	s.stateTracker.acknowledged = false
	s.lastStableStatus = "waiting"
}

// hasBusyIndicator checks if the terminal shows explicit busy indicators
// This is a quick check used in GetStatus() to detect active processing
//
// Busy indicators for different tools:
// - Claude Code: "esc to interrupt", spinner chars, "Thinking...", "Connecting..."
// - Gemini: Similar spinner patterns
// - Aider: Processing indicators
// - Shell: Running commands (no prompt visible)
func (s *Session) hasBusyIndicator(content string) bool {
	// Get last 10 lines for analysis
	lines := strings.Split(content, "\n")
	start := len(lines) - 10
	if start < 0 {
		start = 0
	}
	recentContent := strings.ToLower(strings.Join(lines[start:], "\n"))

	// ═══════════════════════════════════════════════════════════════════════
	// Text-based busy indicators
	// ═══════════════════════════════════════════════════════════════════════
	busyIndicators := []string{
		"esc to interrupt",   // Claude Code main indicator
		"(esc to interrupt)", // Claude Code in parentheses
		"· esc to interrupt", // With separator
	}

	for _, indicator := range busyIndicators {
		if strings.Contains(recentContent, indicator) {
			return true
		}
	}

	// Check for "Thinking... (Xs · Y tokens)" pattern
	if strings.Contains(recentContent, "thinking") && strings.Contains(recentContent, "tokens") {
		return true
	}

	// Check for "Connecting..." pattern
	if strings.Contains(recentContent, "connecting") && strings.Contains(recentContent, "tokens") {
		return true
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Spinner characters (from cli-spinners "dots" - used by Claude Code)
	// These braille characters animate to show processing
	// ═══════════════════════════════════════════════════════════════════════
	spinnerChars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

	// Only check last 5 lines for spinners (they appear near the bottom)
	last5 := lines
	if len(last5) > 5 {
		last5 = last5[len(last5)-5:]
	}

	for _, line := range last5 {
		for _, spinner := range spinnerChars {
			if strings.Contains(line, spinner) {
				return true
			}
		}
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Additional busy indicators (for other tools)
	// ═══════════════════════════════════════════════════════════════════════

	// Generic "working" indicators that appear in various tools
	workingIndicators := []string{
		"processing",
		"loading",
		"please wait",
		"working",
	}

	// Only match these if they're standalone (not part of other text)
	for _, indicator := range workingIndicators {
		// Check if indicator appears at start of a line (more reliable)
		for _, line := range last5 {
			lineLower := strings.ToLower(strings.TrimSpace(line))
			if strings.HasPrefix(lineLower, indicator) {
				return true
			}
		}
	}

	return false
}

// Precompiled regex patterns for dynamic content stripping
// These are compiled once at package init for performance
var (
	// Matches Claude Code status line: "(45s · 1234 tokens · esc to interrupt)"
	dynamicStatusPattern = regexp.MustCompile(`\([^)]*\d+s\s*·[^)]*tokens[^)]*\)`)

	// Matches "Thinking..." or "Connecting..." with timing info
	thinkingPattern = regexp.MustCompile(`(Thinking|Connecting)[^(]*\([^)]*\)`)
)

// normalizeContent strips ANSI codes, spinner characters, and normalizes whitespace
// This is critical for stable hashing - prevents flickering from:
// 1. Color/style changes in terminal output
// 2. Animated spinner characters (⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏)
// 3. Other non-printing control characters
// 4. Terminal resize (which can add trailing spaces with tmux -J flag)
// 5. Multiple consecutive blank lines
// 6. Dynamic time/token counters (e.g., "45s · 1234 tokens")
func (s *Session) normalizeContent(content string) string {
	// Strip ANSI escape codes first (handles CSI, OSC, and C1 codes)
	result := StripANSI(content)

	// Strip other non-printing control characters
	result = stripControlChars(result)

	// Strip braille spinner characters (used by Claude Code and others)
	// These animate while processing and cause hash changes
	spinners := []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}
	for _, r := range spinners {
		result = strings.ReplaceAll(result, string(r), "")
	}

	// Strip dynamic time/token counters that change every second
	// This prevents flickering when Claude Code shows "(45s · 1234 tokens · esc to interrupt)"
	// which updates to "(46s · 1234 tokens · esc to interrupt)" one second later
	result = dynamicStatusPattern.ReplaceAllString(result, "(STATUS)")
	result = thinkingPattern.ReplaceAllString(result, "$1...")

	// Normalize trailing whitespace per line (fixes resize false positives)
	// tmux capture-pane -J can add trailing spaces when terminal is resized
	lines := strings.Split(result, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}
	result = strings.Join(lines, "\n")

	// Normalize multiple consecutive blank lines to a single blank line
	// This prevents hash changes from cursor position variations
	result = normalizeBlankLines(result)

	return result
}

// normalizeBlankLines collapses runs of 3+ newlines to 2 newlines (one blank line)
func normalizeBlankLines(content string) string {
	// Match 3 or more consecutive newlines and replace with 2
	re := regexp.MustCompile(`\n{3,}`)
	return re.ReplaceAllString(content, "\n\n")
}

// stripControlChars removes all ASCII control characters except for tab, newline,
// and carriage return. This helps stabilize content for hashing.
func stripControlChars(content string) string {
	var result strings.Builder
	result.Grow(len(content))
	for _, r := range content {
		// Keep printable characters (space and above), and essential whitespace.
		// DEL (127) is excluded.
		if (r >= 32 && r != 127) || r == '\t' || r == '\n' || r == '\r' {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// hashContent generates SHA256 hash of content (same as Claude Squad)
func (s *Session) hashContent(content string) string {
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:])
}

// SendKeys sends keys to the tmux session
// Uses -l flag to treat keys as literal text, preventing tmux special key interpretation
func (s *Session) SendKeys(keys string) error {
	// The -l flag makes tmux treat the string as literal text, not key names
	// This prevents issues like "Enter" being interpreted as the Enter key
	// and provides a layer of safety against tmux special sequences
	cmd := exec.Command("tmux", "send-keys", "-l", "-t", s.Name, keys)
	return cmd.Run()
}

// SendEnter sends an Enter key to the tmux session
func (s *Session) SendEnter() error {
	cmd := exec.Command("tmux", "send-keys", "-t", s.Name, "Enter")
	return cmd.Run()
}

// GetWorkDir returns the working directory of the session
func (s *Session) GetWorkDir() string {
	return s.WorkDir
}

// ListAllSessions returns all Agent Deck tmux sessions
func ListAllSessions() ([]*Session, error) {
	cmd := exec.Command("tmux", "list-sessions", "-F", "#{session_name}")
	output, err := cmd.Output()
	if err != nil {
		// No sessions exist
		if strings.Contains(err.Error(), "no server running") ||
			strings.Contains(err.Error(), "no sessions") {
			return []*Session{}, nil
		}
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var sessions []*Session

	for _, line := range lines {
		if strings.HasPrefix(line, SessionPrefix) {
			displayName := strings.TrimPrefix(line, SessionPrefix)
			// Get session info
			sess := &Session{
				Name:        line,
				DisplayName: displayName,
			}
			// Try to get working directory
			workDirCmd := exec.Command("tmux", "display-message", "-t", line, "-p", "#{pane_current_path}")
			if workDirOutput, err := workDirCmd.Output(); err == nil {
				sess.WorkDir = strings.TrimSpace(string(workDirOutput))
			}
			sessions = append(sessions, sess)
		}
	}

	return sessions, nil
}

// DiscoverAllTmuxSessions returns all tmux sessions (including non-Agent Deck ones)
func DiscoverAllTmuxSessions() ([]*Session, error) {
	cmd := exec.Command("tmux", "list-sessions", "-F", "#{session_name}:#{pane_current_path}")
	output, err := cmd.Output()
	if err != nil {
		// No sessions exist
		if strings.Contains(err.Error(), "no server running") ||
			strings.Contains(err.Error(), "no sessions") {
			return []*Session{}, nil
		}
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var sessions []*Session

	for _, line := range lines {
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		sessionName := parts[0]
		workDir := ""
		if len(parts) == 2 {
			workDir = parts[1]
		}

		// Create session object
		sess := &Session{
			Name:        sessionName,
			DisplayName: sessionName,
			WorkDir:     workDir,
		}

		// If it's an agent-deck session, clean up the display name
		if strings.HasPrefix(sessionName, SessionPrefix) {
			sess.DisplayName = strings.TrimPrefix(sessionName, SessionPrefix)
		}

		sessions = append(sessions, sess)
	}

	return sessions, nil
}
