// Package tracking provides analytics tracking capabilities for fLINK.
// It supports multiple analytics providers through a common interface.
package tracking

// EventData contains the data needed for tracking an event
type EventData struct {
	RemoteAddr string            // The real client IP address (already cleaned)
	UserAgent  string            // User-Agent header
	Referer    string            // Referer header
	Language   string            // Accept-Language header
	URL        string            // The full URL being accessed
	QueryParams map[string][]string // Query parameters for the request
}

// Tracker defines the interface for analytics tracking implementations.
// Implementations should handle tracking asynchronously to avoid impacting performance.
type Tracker interface {
	// TrackEvent tracks a custom event with category, action, and name
	TrackEvent(data EventData, category, action, name string)

	// IsEnabled returns whether tracking is currently enabled
	IsEnabled() bool

	// Name returns the tracker implementation name for logging
	Name() string
}

// NoOpTracker is a tracker that does nothing (used when tracking is disabled)
type NoOpTracker struct{}

func (t *NoOpTracker) TrackEvent(data EventData, category, action, name string) {}
func (t *NoOpTracker) IsEnabled() bool                                          { return false }
func (t *NoOpTracker) Name() string                                             { return "disabled" }

// Config holds configuration for tracking initialization
type Config struct {
	MatomoURL   string
	MatomoToken string
}

// New creates a new tracker based on the provided configuration.
// It automatically detects which tracking service to use based on config.
func New(cfg Config) Tracker {
	if cfg.MatomoURL != "" && cfg.MatomoToken != "" {
		if tracker := NewMatomoTracker(cfg.MatomoURL, cfg.MatomoToken); tracker.IsEnabled() {
			return tracker
		}
	}

	return &NoOpTracker{}
}
