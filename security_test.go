// security_test.go - Security-related tests including:
// - Direct access scenarios
// - Trusted proxy validation  
// - IP spoofing prevention
// - Tracking data cleaning
// - Security headers

package main

import (
	"net/http/httptest"
	"sync"
	"testing"
	
	"github.com/funktionslust/fLINK/tracking"
)

func TestDirectUserAccess(t *testing.T) {
	// Save and restore the trusted proxy checker state
	oldOnce := trustedProxyChecker.once
	oldNets := trustedProxyChecker.nets
	defer func() {
		trustedProxyChecker.once = oldOnce
		trustedProxyChecker.nets = oldNets
	}()

	// Reset state before test
	trustedProxyChecker.once = sync.Once{}
	trustedProxyChecker.nets = nil

	// Initialize with default trusted proxies
	cfg = config{
		trustedProxies: defaultTrustedProxies,
	}
	initTrustedProxies(cfg.trustedProxies)

	tests := []struct {
		name               string
		userIP             string
		xForwardedFor      string
		expectedRemoteAddr string
		description        string
	}{
		{
			name:               "Internet user cannot spoof",
			userIP:             "203.0.113.45:12345", // Public IP
			xForwardedFor:      "1.2.3.4",
			expectedRemoteAddr: "203.0.113.45:12345",
			description:        "Public IPs are not trusted, headers ignored",
		},
		{
			name:               "Private network user CAN spoof",
			userIP:             "192.168.1.100:12345", // Private IP
			xForwardedFor:      "1.2.3.4",
			expectedRemoteAddr: "1.2.3.4", // SPOOFED!
			description:        "Private IPs are trusted by default, headers accepted",
		},
		{
			name:               "Docker network user CAN spoof",
			userIP:             "172.17.0.2:12345", // Docker default
			xForwardedFor:      "8.8.8.8",
			expectedRemoteAddr: "8.8.8.8", // SPOOFED!
			description:        "Docker IPs are trusted by default",
		},
		{
			name:               "Localhost user CAN spoof",
			userIP:             "127.0.0.1:12345",
			xForwardedFor:      "malicious.com",
			expectedRemoteAddr: "malicious.com", // SPOOFED!
			description:        "Localhost is trusted by default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.userIP
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}

			actualRemoteAddr := getRemoteAddr(req)
			if actualRemoteAddr != tt.expectedRemoteAddr {
				t.Errorf("%s\nExpected: %s\nGot: %s",
					tt.description,
					tt.expectedRemoteAddr,
					actualRemoteAddr)
			}
		})
	}
}

func TestDirectAccessRecommendedConfig(t *testing.T) {
	// Save and restore the trusted proxy checker state
	oldOnce := trustedProxyChecker.once
	oldNets := trustedProxyChecker.nets
	defer func() {
		trustedProxyChecker.once = oldOnce
		trustedProxyChecker.nets = oldNets
	}()

	// Reset state before test
	trustedProxyChecker.once = sync.Once{}
	trustedProxyChecker.nets = nil

	// When fLINK is the entry point, trusted proxies should be empty
	cfg = config{
		trustedProxies: "", // No trusted proxies!
	}
	initTrustedProxies(cfg.trustedProxies)

	tests := []struct {
		name               string
		userIP             string
		xForwardedFor      string
		expectedRemoteAddr string
	}{
		{
			name:               "Internet user cannot spoof",
			userIP:             "203.0.113.45:12345",
			xForwardedFor:      "1.2.3.4",
			expectedRemoteAddr: "203.0.113.45:12345",
		},
		{
			name:               "Private network user cannot spoof",
			userIP:             "192.168.1.100:12345",
			xForwardedFor:      "1.2.3.4",
			expectedRemoteAddr: "192.168.1.100:12345", // NOT SPOOFED!
		},
		{
			name:               "Docker user cannot spoof",
			userIP:             "172.17.0.2:12345",
			xForwardedFor:      "8.8.8.8",
			expectedRemoteAddr: "172.17.0.2:12345", // NOT SPOOFED!
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.userIP
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}

			actualRemoteAddr := getRemoteAddr(req)
			if actualRemoteAddr != tt.expectedRemoteAddr {
				t.Errorf("Expected: %s, Got: %s",
					tt.expectedRemoteAddr,
					actualRemoteAddr)
			}
		})
	}
}
// ==================== Tests moved from tracking_test.go ====================

// mockTracker implements the Tracker interface for testing
type mockTracker struct {
	enabled        bool
	lastEventData  tracking.EventData
	lastCategory   string
	lastAction     string
	lastName       string
}

func (m *mockTracker) TrackEvent(data tracking.EventData, category, action, name string) {
	m.lastEventData = data
	m.lastCategory = category
	m.lastAction = action
	m.lastName = name
}

func (m *mockTracker) IsEnabled() bool {
	return m.enabled
}

func (m *mockTracker) Name() string {
	return "mock"
}

func TestTrackEventCleansRemoteAddr(t *testing.T) {
	// Setup
	oldTracker := tracker
	mock := &mockTracker{enabled: true}
	tracker = mock
	defer func() { tracker = oldTracker }()

	// Save and restore the trusted proxy checker state
	oldOnce := trustedProxyChecker.once
	oldNets := trustedProxyChecker.nets
	defer func() {
		trustedProxyChecker.once = oldOnce
		trustedProxyChecker.nets = oldNets
	}()

	// Reset and initialize trusted proxies for this test
	trustedProxyChecker.once = sync.Once{}
	trustedProxyChecker.nets = nil
	initTrustedProxies("127.0.0.1/32")

	tests := []struct {
		name               string
		remoteAddr         string
		xForwardedFor      string
		xRealIP            string
		expectedRemoteAddr string
		expectHeaders      bool
	}{
		{
			name:               "Trusted proxy with X-Forwarded-For",
			remoteAddr:         "127.0.0.1:1234",
			xForwardedFor:      "203.0.113.1, 198.51.100.2",
			xRealIP:            "",
			expectedRemoteAddr: "203.0.113.1",
			expectHeaders:      true,
		},
		{
			name:               "Trusted proxy with X-Real-IP",
			remoteAddr:         "127.0.0.1:1234",
			xForwardedFor:      "",
			xRealIP:            "203.0.113.5",
			expectedRemoteAddr: "203.0.113.5",
			expectHeaders:      true,
		},
		{
			name:               "Untrusted proxy strips headers",
			remoteAddr:         "198.51.100.1:1234",
			xForwardedFor:      "203.0.113.1",
			xRealIP:            "203.0.113.5",
			expectedRemoteAddr: "198.51.100.1:1234",
			expectHeaders:      false,
		},
		{
			name:               "Direct connection",
			remoteAddr:         "203.0.113.1:1234",
			xForwardedFor:      "",
			xRealIP:            "",
			expectedRemoteAddr: "203.0.113.1:1234",
			expectHeaders:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}
			req.Header.Set("User-Agent", "test-agent")

			// Track event synchronously for testing
			if tracker != nil && tracker.IsEnabled() {
				data := tracking.EventData{
					RemoteAddr:  getRemoteAddr(req),
					UserAgent:   req.Header.Get("User-Agent"),
					Referer:     req.Header.Get("Referer"),
					Language:    req.Header.Get("Accept-Language"),
					URL:         req.URL.String(),
					QueryParams: req.URL.Query(),
				}
				
				tracker.TrackEvent(data, "test", "action", "name")
			}

			// Check remote address was cleaned
			if mock.lastEventData.RemoteAddr != tt.expectedRemoteAddr {
				t.Errorf("Expected RemoteAddr %s, got %s", tt.expectedRemoteAddr, mock.lastEventData.RemoteAddr)
			}

			// Check that user agent was properly captured
			if mock.lastEventData.UserAgent != "test-agent" {
				t.Error("Expected User-Agent to be captured")
			}
		})
	}
}

func TestTrackEventDisabled(t *testing.T) {
	// Setup
	oldTracker := tracker
	mock := &mockTracker{enabled: false}
	tracker = mock
	defer func() { tracker = oldTracker }()

	req := httptest.NewRequest("GET", "/test", nil)
	trackEvent(req, "test", "action", "name")

	if mock.lastEventData.RemoteAddr != "" {
		t.Error("Expected no tracking when disabled")
	}
}

func TestTrackEventNilTracker(t *testing.T) {
	// Setup
	oldTracker := tracker
	tracker = nil
	defer func() { tracker = oldTracker }()

	// Should not panic
	req := httptest.NewRequest("GET", "/test", nil)
	trackEvent(req, "test", "action", "name")
}

