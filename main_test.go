package main

import (
	"bytes"
	"log"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestIsValidPathSegment(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"Valid simple path", "test", true},
		{"Valid with hyphen", "test-123", true},
		{"Valid with underscore", "test_abc", true},
		{"Valid with slash", "blog/post", true},
		{"Valid nested path", "api/v1/users", true},
		{"Empty path", "", false},
		{"Path traversal attempt", "../etc/passwd", false},
		{"Path traversal hidden", "test/../admin", false},
		{"Double dots alone", "..", false},
		{"Contains null byte", "test\x00hack", false},
		{"Too long path", strings.Repeat("a", 2049), false},
		{"URL encoded traversal", "..%2F..%2Fetc", false}, // Rejected due to % encoding
		{"Valid encoded space", "hello%20world", false},   // Rejected due to % encoding
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidPathSegment(tt.path)
			if result != tt.expected {
				t.Errorf("isValidPathSegment(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestIsValidID(t *testing.T) {
	tests := []struct {
		id       string
		expected bool
	}{
		{"test", true},
		{"test-123", true},
		{"test_abc", true},
		{"TestABC123", true},
		{"", false},
		{"test with spaces", false},
		{"test@example", false},
		{"test/path", false},
		{"test?query", false},
		{strings.Repeat("a", 257), false}, // too long
	}

	for _, tt := range tests {
		result := isValidID(tt.id)
		if result != tt.expected {
			t.Errorf("isValidID(%q) = %v, want %v", tt.id, result, tt.expected)
		}
	}
}

func TestIsValidURL(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"https://example.com", true},
		{"http://example.com", true},
		{"https://example.com/path", true},
		{"", false},
		{"ftp://example.com", false},
		{"example.com", false},
		{strings.Repeat("a", 2049), false}, // too long
	}

	for _, tt := range tests {
		result := isValidURL(tt.url)
		if result != tt.expected {
			t.Errorf("isValidURL(%q) = %v, want %v", tt.url, result, tt.expected)
		}
	}
}

func TestParseStatusCode(t *testing.T) {
	tests := []struct {
		input       string
		expected    int
		shouldError bool
	}{
		{"301", 301, false},
		{"302", 302, false},
		{"303", 303, false},
		{"307", 307, false},
		{"308", 308, false},
		{"200", 0, true},
		{"404", 0, true},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		result, err := parseStatusCode(tt.input)
		if tt.shouldError {
			if err == nil {
				t.Errorf("parseStatusCode(%q) expected error but got none", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("parseStatusCode(%q) unexpected error: %v", tt.input, err)
			}
			if result != tt.expected {
				t.Errorf("parseStatusCode(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		}
	}
}

func TestParseMappingLine(t *testing.T) {
	tests := []struct {
		name            string
		line            string
		expectValid     bool
		expectedURL     string
		expectedStatus  int
		expectedPattern bool
	}{
		{"Valid mapping", "test=https://example.com", true, "https://example.com", 302, false},
		{"With custom status", "demo=https://google.com,status=302", true, "https://google.com", 302, false},
		{"With permanent redirect", "old=https://new.com,permanent", true, "https://new.com", 301, false},
		{"Wildcard pattern", "blog/*=https://new.com/articles/*", true, "https://new.com/articles/*", 302, true},
		{"Invalid - no equals", "invalid", false, "", 0, false},
		{"Invalid - no key", "=no-key", false, "", 0, false},
		{"Invalid - no value", "no-value=", false, "", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, ok := parseMappingLine(tt.line)
			if ok != tt.expectValid {
				t.Errorf("Expected validity %v, got %v", tt.expectValid, ok)
				return
			}
			if !tt.expectValid {
				return
			}
			if rule.url != tt.expectedURL {
				t.Errorf("Expected URL %q, got %q", tt.expectedURL, rule.url)
			}
			if rule.status != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rule.status)
			}
			if rule.isPattern != tt.expectedPattern {
				t.Errorf("Expected isPattern %v, got %v", tt.expectedPattern, rule.isPattern)
			}
		})
	}
}

func TestParseAndSetMappings(t *testing.T) {
	data := `
# This is a comment
test=https://example.com
demo=https://google.com,status=302

# Another comment
multi=https://site.com,status=307
`

	parseAndSetMappings(data)

	// Check that rules were loaded
	rule1, ok1, _ := ruleSet.Match("test")
	if !ok1 || rule1.url != "https://example.com" {
		t.Errorf("Expected test rule, got %v", rule1)
	}

	rule2, ok2, _ := ruleSet.Match("demo")
	if !ok2 || rule2.url != "https://google.com" {
		t.Errorf("Expected demo rule, got %v", rule2)
	}

	// Test semicolon separation
	parseAndSetMappings("a=https://a.com;b=https://b.com,status=303")
	ruleA, okA, _ := ruleSet.Match("a")
	if !okA || ruleA.url != "https://a.com" {
		t.Errorf("Expected 'a' rule after semicolon test")
	}
}

func TestHandleRequest(t *testing.T) {
	// Setup test rules
	parseAndSetMappings("test=https://example.com,status=301;demo=https://google.com,status=302")

	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
		expectedLoc    string
	}{
		{"Valid redirect", "GET", "/test", 301, "https://example.com"},
		{"Valid redirect with custom status", "GET", "/demo", 302, "https://google.com"},
		{"Not found", "GET", "/nonexistent", 404, ""},
		{"Method not allowed", "POST", "/test", 405, ""},
		{"Empty path", "GET", "/", 404, ""},
		{"QR code request", "GET", "/test/qr", 200, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			handleRequest(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedLoc != "" {
				location := w.Header().Get("Location")
				if location != tt.expectedLoc {
					t.Errorf("Expected location %q, got %q", tt.expectedLoc, location)
				}
			}

			// Check QR code response
			if strings.HasSuffix(tt.path, "/qr") && tt.expectedStatus == 200 {
				contentType := w.Header().Get("Content-Type")
				if contentType != "image/png" {
					t.Errorf("Expected Content-Type image/png, got %s", contentType)
				}
			}
		})
	}
}

func TestQRCodeGeneration(t *testing.T) {
	// Setup test rules
	parseAndSetMappings("test=https://example.com,status=301")

	req := httptest.NewRequest("GET", "/test/qr", nil)
	req.Host = "short.ly"
	w := httptest.NewRecorder()

	handleRequest(w, req)

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "image/png" {
		t.Errorf("Expected Content-Type image/png, got %s", contentType)
	}

	// Check that we got some PNG data
	body := w.Body.Bytes()
	if len(body) == 0 {
		t.Error("Expected QR code data, got empty response")
	}

	// Check PNG header
	if len(body) < 8 || string(body[:8]) != "\x89PNG\r\n\x1a\n" {
		t.Error("Response doesn't appear to be a valid PNG")
	}
}

func TestQRCodeNotFound(t *testing.T) {
	// Setup test rules
	parseAndSetMappings("test=https://example.com,status=301")

	req := httptest.NewRequest("GET", "/nonexistent/qr", nil)
	w := httptest.NewRecorder()

	handleRequest(w, req)

	if w.Code != 404 {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestPrintBanner(t *testing.T) {
	// Test that printBanner doesn't panic
	printBanner()
}

func TestQueryParameterForwarding(t *testing.T) {
	// Setup config with query parameter forwarding enabled
	cfg = config{
		forwardQueryParams: true,
	}

	// Setup test rules
	parseAndSetMappings("search=https://google.com/search,status=301;home=https://example.com,status=302")

	tests := []struct {
		name        string
		path        string
		expectedLoc string
	}{
		{"No query params", "/home", "https://example.com"},
		{"Single query param", "/home?test=value", "https://example.com?test=value"},
		{"Multiple query params", "/home?a=1&b=2", "https://example.com?a=1&b=2"},
		{"URL with existing params", "/search?q=golang", "https://google.com/search?q=golang"},
		{"Complex query string", "/home?user=john&tab=profile&sort=name", "https://example.com?sort=name&tab=profile&user=john"},
		{"URL encoded params", "/home?name=John%20Doe&city=New%20York", "https://example.com?city=New+York&name=John+Doe"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()

			handleRequest(w, req)

			if w.Code != 301 && w.Code != 302 {
				t.Errorf("Expected redirect status, got %d", w.Code)
				return
			}

			location := w.Header().Get("Location")
			if location != tt.expectedLoc {
				t.Errorf("Expected location %q, got %q", tt.expectedLoc, location)
			}
		})
	}
}

func TestQueryParameterForwardingWithExistingParams(t *testing.T) {
	// Setup config with query parameter forwarding enabled
	cfg = config{
		forwardQueryParams: true,
	}

	// Test URL that already has query parameters
	parseAndSetMappings("search=https://google.com/search?q=flink,status=301")

	tests := []struct {
		name        string
		path        string
		expectedLoc string
	}{
		{"No additional params", "/search", "https://google.com/search?q=flink"},
		{"Additional params", "/search?lang=en", "https://google.com/search?lang=en&q=flink"},
		{"Multiple additional params", "/search?lang=en&safe=on", "https://google.com/search?lang=en&q=flink&safe=on"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()

			handleRequest(w, req)

			if w.Code != 301 {
				t.Errorf("Expected status 301, got %d", w.Code)
				return
			}

			location := w.Header().Get("Location")
			if location != tt.expectedLoc {
				t.Errorf("Expected location %q, got %q", tt.expectedLoc, location)
			}
		})
	}
}

func TestWatchFileForChanges(t *testing.T) {
	// Create temporary file
	tmpfile, err := os.CreateTemp("", "test-watch")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	// Write initial content
	content := "test=https://example.com"
	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Test file watching - this is mainly to test that it doesn't panic
	// We can't easily test the actual watching without complex setup
	done := make(chan bool, 1)
	go func() {
		// Run for a very short time
		watchFileForChanges(tmpfile.Name(), 1*time.Millisecond)
		done <- true
	}()

	// Give it a moment to start
	time.Sleep(10 * time.Millisecond)
	// The function runs indefinitely, so we can't wait for completion
	// This test mainly ensures the function doesn't crash
}

func TestLoadFileMappings(t *testing.T) {
	// Create temporary file
	content := "test=https://example.com\ndemo=https://google.com,status=302"
	tmpfile, err := os.CreateTemp("", "test-mappings")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Test loading
	loadFileMappings(tmpfile.Name())

	// Check rules were loaded
	rule1, ok1, _ := ruleSet.Match("test")
	if !ok1 || rule1.url != "https://example.com" {
		t.Errorf("Expected test rule to be loaded")
	}
	rule2, ok2, _ := ruleSet.Match("demo")
	if !ok2 || rule2.url != "https://google.com" {
		t.Errorf("Expected demo rule to be loaded")
	}

	// Test loading non-existent file (should not panic)
	loadFileMappings("/non/existent/file")
}

func TestGetEnv(t *testing.T) {
	// Test with existing env var
	os.Setenv("TEST_VAR", "test_value")
	defer os.Unsetenv("TEST_VAR")

	result := getEnv("TEST_VAR", "default")
	if result != "test_value" {
		t.Errorf("Expected 'test_value', got %q", result)
	}

	// Test with non-existent env var
	result = getEnv("NON_EXISTENT_VAR", "default")
	if result != "default" {
		t.Errorf("Expected 'default', got %q", result)
	}
}

func TestGetHostname(t *testing.T) {
	// Set up trusted proxies for testing
	parseTrustedProxies("127.0.0.1")

	tests := []struct {
		name       string
		headers    map[string]string
		host       string
		remoteAddr string
		expected   string
	}{
		{"X-Forwarded-Host", map[string]string{"X-Forwarded-Host": "proxy.example.com"}, "", "127.0.0.1:1234", "proxy.example.com"},
		{"X-Original-Host", map[string]string{"X-Original-Host": "original.example.com"}, "", "127.0.0.1:1234", "original.example.com"},
		{"Host header", map[string]string{}, "direct.example.com", "127.0.0.1:1234", "direct.example.com"},
		{"Fallback", map[string]string{}, "", "127.0.0.1:1234", "localhost:8080"},
		{"Untrusted proxy ignores forwarded", map[string]string{"X-Forwarded-Host": "evil.com"}, "safe.com", "8.8.8.8:443", "safe.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Host = tt.host
			req.RemoteAddr = tt.remoteAddr
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			result := getHostname(req)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestGetPathPrefix(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected string
	}{
		{"No prefix", map[string]string{}, ""},
		{"X-Forwarded-Prefix", map[string]string{"X-Forwarded-Prefix": "/s"}, "/s"},
		{"X-Forwarded-Path full", map[string]string{"X-Forwarded-Path": "/s/test"}, "/s"},
		{"X-Forwarded-Path single", map[string]string{"X-Forwarded-Path": "/test"}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			result := getPathPrefix(req)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestGetRemoteAddr(t *testing.T) {
	// Set up trusted proxies for testing
	parseTrustedProxies("127.0.0.1")

	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expected   string
	}{
		{"X-Forwarded-For single", map[string]string{"X-Forwarded-For": "203.0.113.1"}, "127.0.0.1:1234", "203.0.113.1"},
		{"X-Forwarded-For multiple", map[string]string{"X-Forwarded-For": "203.0.113.1, 203.0.113.2"}, "127.0.0.1:1234", "203.0.113.1"},
		{"X-Real-IP", map[string]string{"X-Real-IP": "203.0.113.3"}, "127.0.0.1:1234", "203.0.113.3"},
		{"RemoteAddr fallback", map[string]string{}, "203.0.113.4:1234", "203.0.113.4:1234"},
		{"Untrusted proxy ignores headers", map[string]string{"X-Forwarded-For": "fake.ip"}, "8.8.8.8:443", "8.8.8.8:443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			result := getRemoteAddr(req)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestLogAccess(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	// Test request
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("User-Agent", "test-agent")
	req.RemoteAddr = "192.0.2.1:1234"

	// Test redirect log
	logAccess(req, 301, time.Millisecond, "redirect", "https://example.com", "")
	output := buf.String()
	if !strings.Contains(output, "192.0.2.1") {
		t.Error("Log should contain remote address")
	}
	if !strings.Contains(output, "→ https://example.com") {
		t.Error("Log should contain redirect destination")
	}
	if !strings.Contains(output, "(301)") {
		t.Error("Log should contain status code")
	}

	// Test error log
	buf.Reset()
	logAccess(req, 404, time.Microsecond, "error", "", "not found")
	output = buf.String()
	if !strings.Contains(output, "ERROR: not found") {
		t.Error("Log should contain error message")
	}

	// Test QR log
	buf.Reset()
	logAccess(req, 200, time.Millisecond, "qr", "https://example.com/test", "")
	output = buf.String()
	if !strings.Contains(output, "→ QR:https://example.com/test") {
		t.Error("Log should contain QR destination")
	}
}

func TestConcurrentAccess(t *testing.T) {
	// Test concurrent read/write access to rules
	parseAndSetMappings("test=https://example.com,status=301")

	done := make(chan bool, 2)

	// Goroutine 1: Read rules
	go func() {
		for i := 0; i < 100; i++ {
			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			handleRequest(w, req)
			time.Sleep(time.Microsecond)
		}
		done <- true
	}()

	// Goroutine 2: Update rules
	go func() {
		for i := 0; i < 10; i++ {
			parseAndSetMappings("test=https://example.com\nnew=https://new.com")
			time.Sleep(time.Millisecond)
		}
		done <- true
	}()

	// Wait for both goroutines
	<-done
	<-done
}

func BenchmarkHandleRequest(b *testing.B) {
	parseAndSetMappings("test=https://example.com,status=301")

	req := httptest.NewRequest("GET", "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handleRequest(w, req)
	}
}

func BenchmarkQRGeneration(b *testing.B) {
	parseAndSetMappings("test=https://example.com,status=301")

	req := httptest.NewRequest("GET", "/test/qr", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handleRequest(w, req)
	}
}

func TestCommonHeaders(t *testing.T) {
	// Setup test rules
	parseAndSetMappings("test=https://example.com,status=301")

	tests := []struct {
		name           string
		path           string
		expectedStatus int
	}{
		{"redirect", "/test", 301},
		{"not found", "/nonexistent", 404},
		{"qr code", "/test/qr", 200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			rr := httptest.NewRecorder()

			handleRequest(rr, req)

			// Check common headers
			if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %v, want nosniff", got)
			}
			if got := rr.Header().Get("X-Frame-Options"); got != "DENY" {
				t.Errorf("X-Frame-Options = %v, want DENY", got)
			}
			if got := rr.Header().Get("X-Powered-By"); got != "fLINK by Funktionslust GmbH" {
				t.Errorf("X-Powered-By = %v, want fLINK by Funktionslust GmbH", got)
			}
			if got := rr.Header().Get("Server"); !strings.HasPrefix(got, "fLINK/") {
				t.Errorf("Server = %v, want fLINK/xxx", got)
			}
		})
	}
}

func BenchmarkIsValidID(b *testing.B) {
	testID := "test-123_abc"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isValidID(testID)
	}
}

// TestWildcardMatching tests the wildcard pattern matching functionality
func TestWildcardMatching(t *testing.T) {
	// Initialize config
	cfg = config{
		forwardQueryParams: true,
	}

	tests := []struct {
		name           string
		mappings       string
		requestPath    string
		expectedStatus int
		expectedDest   string
	}{
		{
			name:           "Exact match takes precedence over wildcard",
			mappings:       "blog/hello=https://exact.com;blog/*=https://pattern.com/*",
			requestPath:    "/blog/hello",
			expectedStatus: 302,
			expectedDest:   "https://exact.com",
		},
		{
			name:           "Wildcard with suffix preservation",
			mappings:       "blog/*=https://new.com/articles/*",
			requestPath:    "/blog/my-post",
			expectedStatus: 302,
			expectedDest:   "https://new.com/articles/my-post",
		},
		{
			name:           "Wildcard with nested path preservation",
			mappings:       "blog/*=https://new.com/articles/*",
			requestPath:    "/blog/2024/12/post",
			expectedStatus: 302,
			expectedDest:   "https://new.com/articles/2024/12/post",
		},
		{
			name:           "Wildcard without suffix in destination (drops suffix)",
			mappings:       "old/*=https://new.com/deprecated",
			requestPath:    "/old/anything/here",
			expectedStatus: 302,
			expectedDest:   "https://new.com/deprecated",
		},
		{
			name:           "More specific pattern wins",
			mappings:       "api/v1/*=https://v1.api.com/*;api/*=https://api.com/*",
			requestPath:    "/api/v1/users",
			expectedStatus: 302,
			expectedDest:   "https://v1.api.com/users",
		},
		{
			name:           "Less specific pattern matches when more specific doesn't",
			mappings:       "api/v1/*=https://v1.api.com/*;api/*=https://api.com/*",
			requestPath:    "/api/v2/users",
			expectedStatus: 302,
			expectedDest:   "https://api.com/v2/users",
		},
		{
			name:           "Catch-all pattern",
			mappings:       "specific=https://specific.com;/*=https://catchall.com/*",
			requestPath:    "/random/path",
			expectedStatus: 302,
			expectedDest:   "https://catchall.com/random/path",
		},
		{
			name:           "Wildcard with permanent redirect",
			mappings:       "old/*=https://new.com/*,permanent",
			requestPath:    "/old/page",
			expectedStatus: 301,
			expectedDest:   "https://new.com/page",
		},
		{
			name:           "Root wildcard matches everything",
			mappings:       "*=https://default.com/*",
			requestPath:    "/any/path/here",
			expectedStatus: 302,
			expectedDest:   "https://default.com/any/path/here",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse mappings
			parseAndSetMappings(tt.mappings)

			// Create test request
			req := httptest.NewRequest("GET", tt.requestPath, nil)
			req.RemoteAddr = "192.0.2.1:1234"
			rr := httptest.NewRecorder()

			// Handle request
			handleRequest(rr, req)

			// Check status code
			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			// Check redirect location
			if tt.expectedStatus == 301 || tt.expectedStatus == 302 {
				location := rr.Header().Get("Location")
				if location != tt.expectedDest {
					t.Errorf("Expected redirect to %s, got %s", tt.expectedDest, location)
				}
			}
		})
	}
}

// TestRedirectTypeAliases tests the named redirect type aliases
func TestRedirectTypeAliases(t *testing.T) {
	tests := []struct {
		name         string
		statusAlias  string
		expectedCode int
		shouldError  bool
	}{
		{"Permanent alias", "permanent", 301, false},
		{"Temporary alias", "temporary", 302, false},
		{"Temp short alias", "temp", 302, false},
		{"See-other alias", "see-other", 303, false},
		{"Temporary-strict alias", "temporary-strict", 307, false},
		{"Permanent-strict alias", "permanent-strict", 308, false},
		{"Numeric 301", "301", 301, false},
		{"Numeric 302", "302", 302, false},
		{"Numeric 303", "303", 303, false},
		{"Numeric 307", "307", 307, false},
		{"Numeric 308", "308", 308, false},
		{"Invalid alias", "invalid", 0, true},
		{"Invalid number", "400", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, err := parseStatusCode(tt.statusAlias)

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error for %s, but got none", tt.statusAlias)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for %s: %v", tt.statusAlias, err)
				}
				if code != tt.expectedCode {
					t.Errorf("Expected code %d for %s, got %d", tt.expectedCode, tt.statusAlias, code)
				}
			}
		})
	}
}

// TestTrustedProxyValidation tests the trusted proxy IP validation
func TestTrustedProxyValidation(t *testing.T) {
	// Set up trusted proxies
	err := parseTrustedProxies("10.0.0.0/8,192.168.0.0/16,127.0.0.1")
	if err != nil {
		t.Fatalf("Failed to parse trusted proxies: %v", err)
	}

	tests := []struct {
		name          string
		remoteAddr    string
		expectTrusted bool
	}{
		{"Local loopback", "127.0.0.1:1234", true},
		{"Private 10.x", "10.0.0.5:8080", true},
		{"Private 192.168.x", "192.168.1.100:3000", true},
		{"Public IP", "8.8.8.8:443", false},
		{"Another public IP", "1.2.3.4:80", false},
		{"Private 172.16.x not in list", "172.16.1.1:80", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trusted := isTrustedProxy(tt.remoteAddr)
			if trusted != tt.expectTrusted {
				t.Errorf("Expected isTrustedProxy(%s) = %v, got %v",
					tt.remoteAddr, tt.expectTrusted, trusted)
			}
		})
	}
}

// TestForwardedHeaders tests that forwarded headers are only trusted from trusted proxies
func TestForwardedHeaders(t *testing.T) {
	// Set up trusted proxies
	err := parseTrustedProxies("127.0.0.1")
	if err != nil {
		t.Fatalf("Failed to parse trusted proxies: %v", err)
	}

	tests := []struct {
		name          string
		remoteAddr    string
		forwardedHost string
		forwardedFor  string
		expectedHost  string
		expectedIP    string
	}{
		{
			name:          "Trusted proxy - use forwarded headers",
			remoteAddr:    "127.0.0.1:1234",
			forwardedHost: "forwarded.example.com",
			forwardedFor:  "203.0.113.1",
			expectedHost:  "forwarded.example.com",
			expectedIP:    "203.0.113.1",
		},
		{
			name:          "Untrusted proxy - ignore forwarded headers",
			remoteAddr:    "8.8.8.8:443",
			forwardedHost: "evil.example.com",
			forwardedFor:  "203.0.113.1",
			expectedHost:  "test.example.com", // Should use Host header
			expectedIP:    "8.8.8.8:443",      // Should use RemoteAddr
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			req.Host = "test.example.com"
			if tt.forwardedHost != "" {
				req.Header.Set("X-Forwarded-Host", tt.forwardedHost)
			}
			if tt.forwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.forwardedFor)
			}

			host := getHostname(req)
			if host != tt.expectedHost {
				t.Errorf("Expected host %s, got %s", tt.expectedHost, host)
			}

			ip := getRemoteAddr(req)
			if ip != tt.expectedIP {
				t.Errorf("Expected IP %s, got %s", tt.expectedIP, ip)
			}
		})
	}
}

// TestWildcardWithQueryParams tests that query parameters work with wildcards
func TestWildcardWithQueryParams(t *testing.T) {
	cfg = config{
		forwardQueryParams: true,
	}

	// Set up a wildcard redirect
	parseAndSetMappings("api/*=https://backend.com/v2/*")

	req := httptest.NewRequest("GET", "/api/users?limit=10&offset=20", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	rr := httptest.NewRecorder()

	handleRequest(rr, req)

	if rr.Code != 302 {
		t.Errorf("Expected status 302, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	expected := "https://backend.com/v2/users?limit=10&offset=20"
	if location != expected {
		t.Errorf("Expected location %s, got %s", expected, location)
	}
}

func TestSecurityHeaders(t *testing.T) {
	// Setup test rule
	parseAndSetMappings("test=https://example.com")

	tests := []struct {
		name   string
		path   string
		method string
	}{
		{"Redirect request", "/test", "GET"},
		{"Not found request", "/notfound", "GET"},
		{"Method not allowed", "/test", "POST"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.RemoteAddr = "127.0.0.1:1234"
			rr := httptest.NewRecorder()

			handleRequest(rr, req)

			// Check security headers are always present
			if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %v, want nosniff", got)
			}
			if got := rr.Header().Get("X-Frame-Options"); got != "DENY" {
				t.Errorf("X-Frame-Options = %v, want DENY", got)
			}
		})
	}
}

func TestLoadInlineMappings(t *testing.T) {
	// Test inline mappings loading
	loadInlineMappings("test=https://example.com;demo=https://demo.com,permanent")

	// Check rules were loaded
	rule1, ok1, _ := ruleSet.Match("test")
	if !ok1 || rule1.url != "https://example.com" || rule1.status != 302 {
		t.Errorf("Expected test rule with 302 status")
	}

	rule2, ok2, _ := ruleSet.Match("demo")
	if !ok2 || rule2.url != "https://demo.com" || rule2.status != 301 {
		t.Errorf("Expected demo rule with 301 status")
	}
}
