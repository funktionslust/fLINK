// Package tracking provides analytics tracking capabilities for fLINK.
// It supports multiple analytics providers through a common interface.
package tracking

import (
	"net/http"
)

// Tracker defines the interface for analytics tracking implementations.
// Implementations should handle tracking asynchronously to avoid impacting performance.
type Tracker interface {
	// TrackEvent tracks a custom event with category, action, and name
	TrackEvent(r *http.Request, category, action, name string)

	// IsEnabled returns whether tracking is currently enabled
	IsEnabled() bool

	// Name returns the tracker implementation name for logging
	Name() string
}

// NoOpTracker is a tracker that does nothing (used when tracking is disabled)
type NoOpTracker struct{}

func (t *NoOpTracker) TrackEvent(r *http.Request, category, action, name string) {}
func (t *NoOpTracker) IsEnabled() bool                                           { return false }
func (t *NoOpTracker) Name() string                                              { return "disabled" }

// Config holds configuration for tracking initialization
type Config struct {
	// Matomo configuration
	MatomoURL   string
	MatomoToken string

	// Future: Google Analytics, Plausible, etc.
}

// New creates a new tracker based on the provided configuration.
// It automatically detects which tracking service to use based on config.
func New(cfg Config) Tracker {
	// Try Matomo first
	if cfg.MatomoURL != "" && cfg.MatomoToken != "" {
		if tracker := NewMatomoTracker(cfg.MatomoURL, cfg.MatomoToken); tracker.IsEnabled() {
			return tracker
		}
	}

	// Future: Try other trackers
	// if cfg.GoogleAnalyticsID != "" { ... }
	// if cfg.PlausibleDomain != "" { ... }

	return &NoOpTracker{}
}
