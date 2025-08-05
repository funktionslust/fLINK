package main

import (
	"log"
	"net/http"

	"github.com/funktionslust/fLINK/tracking"
)

// tracker holds the active tracking implementation
var tracker tracking.Tracker

// initTracking initializes the tracking system based on configuration
func initTracking(cfg config) {
	// Build tracking configuration from main config
	trackingConfig := tracking.Config{
		MatomoURL:   cfg.matomoURL,
		MatomoToken: cfg.matomoToken,
	}

	// The tracking package will automatically detect which service to use
	// based on which credentials are provided
	tracker = tracking.New(trackingConfig)

	// Log which tracking is enabled (if any)
	if tracker.IsEnabled() {
		log.Printf("Tracking enabled: %s", tracker.Name())
	} else {
		log.Printf("Tracking disabled")
	}
}

// trackEvent is a convenience function to track events using the active tracker
func trackEvent(r *http.Request, category, action, name string) {
	if tracker != nil && tracker.IsEnabled() {
		// Build event data with cleaned information
		data := tracking.EventData{
			RemoteAddr:  getRemoteAddr(r), // clean using trusted proxy
			UserAgent:   r.Header.Get("User-Agent"),
			Referer:     r.Header.Get("Referer"),
			Language:    r.Header.Get("Accept-Language"),
			URL:         r.URL.String(),
			QueryParams: r.URL.Query(),
		}

		go tracker.TrackEvent(data, category, action, name)
	}
}
