package main

import (
	"net/http"
	"os"
	"strings"

	"github.com/funktionslust/fLINK/tracking"
)

// tracker holds the active tracking implementation
var tracker tracking.Tracker

// initTracking initializes the tracking system based on configuration
func initTracking() {
	cfg := tracking.Config{
		MatomoURL:   getEnvOrFile("MATOMO_URL"),
		MatomoToken: getEnvOrFile("MATOMO_TOKEN"),
	}

	tracker = tracking.New(cfg)
}

// trackEvent is a convenience function to track events using the active tracker
func trackEvent(r *http.Request, category, action, name string) {
	if tracker != nil && tracker.IsEnabled() {
		go tracker.TrackEvent(r, category, action, name)
	}
}

// getEnvOrFile reads a value from environment variable or from a file specified by envVar_FILE.
// This pattern is commonly used in containerized environments for secret management.
func getEnvOrFile(envVar string) string {
	// First try to get value directly from environment variable
	if value := os.Getenv(envVar); value != "" {
		return value
	}

	// Then try to read from file specified in envVar_FILE
	if fileVar := os.Getenv(envVar + "_FILE"); fileVar != "" {
		content, err := os.ReadFile(fileVar)
		if err != nil {
			// Silent fail - logging happens in the tracking package
			return ""
		}
		return strings.TrimSpace(string(content))
	}

	return ""
}
