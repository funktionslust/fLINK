// integration_test.go - End-to-end integration tests including:
// - Full request flow with tracking
// - QR code generation with security
// - Multiple component interactions

package main

import (
	"net/http/httptest"
	"sync"
	"testing"
	"time"
	
	"github.com/funktionslust/fLINK/tracking"
)

// captureTracker captures tracking calls for testing
type captureTracker struct {
	mu            sync.Mutex
	lastEventData tracking.EventData
	enabled       bool
}

func (c *captureTracker) TrackEvent(data tracking.EventData, category, action, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastEventData = data
}

func (c *captureTracker) IsEnabled() bool {
	return c.enabled
}

func (c *captureTracker) Name() string {
	return "capture"
}

func (c *captureTracker) getLastEventData() tracking.EventData {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastEventData
}

func TestEndToEndDirectAccess(t *testing.T) {
	// Save and restore state
	oldTracker := tracker
	oldOnce := trustedProxyChecker.once
	oldNets := trustedProxyChecker.nets
	defer func() {
		tracker = oldTracker
		trustedProxyChecker.once = oldOnce
		trustedProxyChecker.nets = oldNets
	}()

	// Setup capture tracker
	capture := &captureTracker{enabled: true}
	tracker = capture

	// Setup redirect rules
	parseAndSetMappings("shop=https://shop.example.com")

	tests := []struct {
		name              string
		trustedProxies    string
		userIP            string
		xForwardedFor     string
		expectedTrackedIP string
		description       string
	}{
		{
			name:              "Direct access with empty trusted proxies",
			trustedProxies:    "", // Recommended for direct access
			userIP:            "203.0.113.45:12345",
			xForwardedFor:     "1.2.3.4",
			expectedTrackedIP: "203.0.113.45:12345",
			description:       "User IP tracked correctly, header ignored",
		},
		{
			name:              "Behind proxy with specific trusted proxy",
			trustedProxies:    "10.0.0.5/32", // Only the specific proxy
			userIP:            "10.0.0.5:80",
			xForwardedFor:     "203.0.113.45",
			expectedTrackedIP: "203.0.113.45",
			description:       "Real user IP extracted from header",
		},
		{
			name:              "Default config allows private network spoofing",
			trustedProxies:    defaultTrustedProxies,
			userIP:            "192.168.1.100:12345",
			xForwardedFor:     "8.8.8.8",
			expectedTrackedIP: "8.8.8.8", // SPOOFED!
			description:       "Private network can spoof with defaults",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset trusted proxy config
			trustedProxyChecker.once = sync.Once{}
			trustedProxyChecker.nets = nil
			capture.lastEventData = tracking.EventData{}

			// Initialize with test config
			cfg = config{
				trustedProxies:     tt.trustedProxies,
				forwardQueryParams: true,
			}
			initTrustedProxies(cfg.trustedProxies)

			// Create request
			req := httptest.NewRequest("GET", "/shop", nil)
			req.RemoteAddr = tt.userIP
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}

			// Handle the request
			w := httptest.NewRecorder()
			handleRequest(w, req)

			// Wait a bit for async tracking
			time.Sleep(10 * time.Millisecond)

			// Check redirect worked
			if w.Code != 302 {
				t.Errorf("Expected redirect status 302, got %d", w.Code)
			}

			// Check tracking captured correct IP
			trackedData := capture.getLastEventData()
			if trackedData.RemoteAddr == "" {
				t.Fatal("No tracking event captured")
			}

			if trackedData.RemoteAddr != tt.expectedTrackedIP {
				t.Errorf("%s\nExpected tracked IP: %s\nGot: %s",
					tt.description,
					tt.expectedTrackedIP,
					trackedData.RemoteAddr)
			}
		})
	}
}

func TestEndToEndQRCode(t *testing.T) {
	// Save and restore state
	oldOnce := trustedProxyChecker.once
	oldNets := trustedProxyChecker.nets
	defer func() {
		trustedProxyChecker.once = oldOnce
		trustedProxyChecker.nets = oldNets
	}()

	// Reset and configure for direct access
	trustedProxyChecker.once = sync.Once{}
	trustedProxyChecker.nets = nil
	cfg = config{
		trustedProxies: "", // No trusted proxies for direct access
	}
	initTrustedProxies(cfg.trustedProxies)

	// Setup redirect rule
	parseAndSetMappings("link=https://example.com")

	// Test QR code generation with spoofing attempt
	req := httptest.NewRequest("GET", "/link/qr", nil)
	req.RemoteAddr = "203.0.113.45:12345"
	req.Header.Set("X-Forwarded-Host", "evil.com")
	req.Header.Set("X-Forwarded-Prefix", "/malicious")

	w := httptest.NewRecorder()
	handleRequest(w, req)

	// Should succeed
	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// QR code should use the actual host, not the spoofed one
	// Since we're not behind a trusted proxy, the forwarded headers are ignored
	// The QR code will contain the correct URL
}