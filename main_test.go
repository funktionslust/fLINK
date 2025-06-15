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
	rules := make(map[string]redirectRule)

	// Test valid mapping
	parseMappingLine("test=https://example.com", rules)
	if len(rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(rules))
	}
	if rule, ok := rules["test"]; ok {
		if rule.url != "https://example.com" {
			t.Errorf("Expected url 'https://example.com', got %q", rule.url)
		}
		if rule.status != 302 {
			t.Errorf("Expected status 302, got %d", rule.status)
		}
	} else {
		t.Error("Rule 'test' not found")
	}

	// Test with custom status
	parseMappingLine("demo=https://google.com,status=302", rules)
	if rule, ok := rules["demo"]; ok {
		if rule.url != "https://google.com" {
			t.Errorf("Expected url 'https://google.com', got %q", rule.url)
		}
		if rule.status != 302 {
			t.Errorf("Expected status 302, got %d", rule.status)
		}
	} else {
		t.Error("Rule 'demo' not found")
	}

	// Test invalid formats
	originalLen := len(rules)
	parseMappingLine("invalid", rules)
	parseMappingLine("=no-key", rules)
	parseMappingLine("no-value=", rules)
	if len(rules) != originalLen {
		t.Errorf("Invalid lines should not add rules")
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

	if len(rules) != 3 {
		t.Errorf("Expected 3 rules, got %d", len(rules))
	}

	// Test semicolon separation
	parseAndSetMappings("a=https://a.com;b=https://b.com,status=303")
	if len(rules) != 2 {
		t.Errorf("Expected 2 rules after semicolon test, got %d", len(rules))
	}
}

func TestHandleRequest(t *testing.T) {
	// Setup test rules
	rules = map[string]redirectRule{
		"test": {url: "https://example.com", status: 301},
		"demo": {url: "https://google.com", status: 302},
	}

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
		{"Invalid ID", "GET", "/test@invalid", 400, ""},
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
	rules = map[string]redirectRule{
		"test": {url: "https://example.com", status: 301},
	}

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
	rules = map[string]redirectRule{
		"test": {url: "https://example.com", status: 301},
	}

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
	// Setup test rules
	rules = map[string]redirectRule{
		"search": {url: "https://google.com/search", status: 301},
		"home":   {url: "https://example.com", status: 302},
	}

	tests := []struct {
		name        string
		path        string
		expectedLoc string
	}{
		{"No query params", "/home", "https://example.com"},
		{"Single query param", "/home?test=value", "https://example.com?test=value"},
		{"Multiple query params", "/home?a=1&b=2", "https://example.com?a=1&b=2"},
		{"URL with existing params", "/search?q=golang", "https://google.com/search?q=golang"},
		{"Complex query string", "/home?user=john&tab=profile&sort=name", "https://example.com?user=john&tab=profile&sort=name"},
		{"URL encoded params", "/home?name=John%20Doe&city=New%20York", "https://example.com?name=John%20Doe&city=New%20York"},
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
	// Test URL that already has query parameters
	rules = map[string]redirectRule{
		"search": {url: "https://google.com/search?q=flink", status: 301},
	}

	tests := []struct {
		name        string
		path        string
		expectedLoc string
	}{
		{"No additional params", "/search", "https://google.com/search?q=flink"},
		{"Additional params", "/search?lang=en", "https://google.com/search?q=flink&lang=en"},
		{"Multiple additional params", "/search?lang=en&safe=on", "https://google.com/search?q=flink&lang=en&safe=on"},
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

	if len(rules) != 2 {
		t.Errorf("Expected 2 rules after loading file, got %d", len(rules))
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
	tests := []struct {
		name     string
		headers  map[string]string
		host     string
		expected string
	}{
		{"X-Forwarded-Host", map[string]string{"X-Forwarded-Host": "proxy.example.com"}, "", "proxy.example.com"},
		{"X-Original-Host", map[string]string{"X-Original-Host": "original.example.com"}, "", "original.example.com"},
		{"Host header", map[string]string{}, "direct.example.com", "direct.example.com"},
		{"Fallback", map[string]string{}, "", "localhost:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Host = tt.host
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
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expected   string
	}{
		{"X-Forwarded-For single", map[string]string{"X-Forwarded-For": "203.0.113.1"}, "", "203.0.113.1"},
		{"X-Forwarded-For multiple", map[string]string{"X-Forwarded-For": "203.0.113.1, 203.0.113.2"}, "", "203.0.113.1"},
		{"X-Real-IP", map[string]string{"X-Real-IP": "203.0.113.3"}, "", "203.0.113.3"},
		{"RemoteAddr fallback", map[string]string{}, "203.0.113.4:1234", "203.0.113.4:1234"},
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
	rules = map[string]redirectRule{
		"test": {url: "https://example.com", status: 301},
	}

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
	rules = map[string]redirectRule{
		"test": {url: "https://example.com", status: 301},
	}

	req := httptest.NewRequest("GET", "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handleRequest(w, req)
	}
}

func BenchmarkQRGeneration(b *testing.B) {
	rules = map[string]redirectRule{
		"test": {url: "https://example.com", status: 301},
	}

	req := httptest.NewRequest("GET", "/test/qr", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handleRequest(w, req)
	}
}

func TestCommonHeaders(t *testing.T) {
	// Setup test rules
	rulesMu.Lock()
	rules = map[string]redirectRule{
		"test": {url: "https://example.com", status: 301},
	}
	rulesMu.Unlock()

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
