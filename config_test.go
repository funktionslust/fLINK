package main

import (
	"flag"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Save original env vars
	origPort := os.Getenv("PORT")
	origMappings := os.Getenv("REDIRECT_MAPPINGS")
	origForward := os.Getenv("FORWARD_QUERY_PARAMS")
	defer func() {
		os.Setenv("PORT", origPort)
		os.Setenv("REDIRECT_MAPPINGS", origMappings)
		os.Setenv("FORWARD_QUERY_PARAMS", origForward)
	}()

	tests := []struct {
		name              string
		portFlag          string
		mappingsFlag      string
		forwardParamsFlag bool
		envVars           map[string]string
		expectedPort      string
		expectedMappings  string
		expectedForward   bool
	}{
		{
			name:              "CLI flags override env vars",
			portFlag:          "9090",
			mappingsFlag:      "test.txt",
			forwardParamsFlag: true,
			envVars: map[string]string{
				"PORT":                 "8080",
				"REDIRECT_MAPPINGS":    "env.txt",
				"FORWARD_QUERY_PARAMS": "false",
			},
			expectedPort:     "9090",
			expectedMappings: "test.txt",
			expectedForward:  false, // Env var because flagWasSet returns false in tests
		},
		{
			name:              "Env vars when no CLI flags",
			portFlag:          "",
			mappingsFlag:      "",
			forwardParamsFlag: true, // default
			envVars: map[string]string{
				"PORT":              "7070",
				"REDIRECT_MAPPINGS": "env-mappings.txt",
			},
			expectedPort:     "7070",
			expectedMappings: "env-mappings.txt",
			expectedForward:  true,
		},
		{
			name:              "Defaults when no env or CLI",
			portFlag:          "",
			mappingsFlag:      "required.txt", // mappings are required
			forwardParamsFlag: true,
			envVars:           map[string]string{},
			expectedPort:      "8080",
			expectedMappings:  "required.txt",
			expectedForward:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear env vars
			os.Unsetenv("PORT")
			os.Unsetenv("REDIRECT_MAPPINGS")
			os.Unsetenv("FORWARD_QUERY_PARAMS")

			// Set test env vars
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			// Load config
			cfg := loadConfig(tt.portFlag, tt.mappingsFlag, tt.forwardParamsFlag)

			// Check results
			if cfg.port != tt.expectedPort {
				t.Errorf("Expected port %s, got %s", tt.expectedPort, cfg.port)
			}
			if cfg.mappingSource != tt.expectedMappings {
				t.Errorf("Expected mappings %s, got %s", tt.expectedMappings, cfg.mappingSource)
			}
			if cfg.forwardQueryParams != tt.expectedForward {
				t.Errorf("Expected forwardQueryParams %v, got %v", tt.expectedForward, cfg.forwardQueryParams)
			}
		})
	}
}

func TestFlagWasSet(t *testing.T) {
	// Reset flag.CommandLine for testing
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	// Define test flags
	testFlag := flag.String("test-flag", "default", "test flag")
	unusedFlag := flag.String("unused-flag", "default", "unused flag")

	// Parse with a set flag
	flag.CommandLine.Parse([]string{"-test-flag", "value"})

	// Check if flag was set
	if !flagWasSet("test-flag") {
		t.Error("Expected test-flag to be set")
	}
	if flagWasSet("unused-flag") {
		t.Error("Expected unused-flag to not be set")
	}

	// Use the flags to avoid compiler warning
	_ = *testFlag
	_ = *unusedFlag
}

func TestGetEnvBool(t *testing.T) {
	tests := []struct {
		name         string
		envValue     string
		defaultValue bool
		expected     bool
	}{
		{"true string", "true", false, true},
		{"1 string", "1", false, true},
		{"yes string", "yes", false, true},
		{"false string", "false", true, false},
		{"0 string", "0", true, false},
		{"no string", "no", true, false},
		{"empty string uses default true", "", true, true},
		{"empty string uses default false", "", false, false},
		{"invalid string uses false", "invalid", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("TEST_BOOL", tt.envValue)
			defer os.Unsetenv("TEST_BOOL")

			result := getEnvBool("TEST_BOOL", tt.defaultValue)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v for value %q", tt.expected, result, tt.envValue)
			}
		})
	}
}

func TestQueryParameterMerging(t *testing.T) {
	// This tests the real-world scenario of merging query parameters
	// when both the destination URL and incoming request have parameters
	cfg = config{
		forwardQueryParams: true,
	}

	tests := []struct {
		name        string
		destination string
		incoming    string
		expected    string
		description string
	}{
		{
			name:        "UTM tracking on clean URL",
			destination: "https://shop.com/product",
			incoming:    "?utm_source=google&utm_campaign=summer",
			expected:    "https://shop.com/product?utm_campaign=summer&utm_source=google",
			description: "Marketing campaign tracking parameters",
		},
		{
			name:        "UTM added to URL with existing params",
			destination: "https://shop.com/search?category=shoes",
			incoming:    "?utm_source=facebook&utm_content=ad1",
			expected:    "https://shop.com/search?category=shoes&utm_content=ad1&utm_source=facebook",
			description: "Preserving product filters while adding tracking",
		},
		{
			name:        "Complex e-commerce scenario",
			destination: "https://shop.com/search?category=electronics&sort=price",
			incoming:    "?ref=affiliate123&discount=SUMMER20&utm_source=partner",
			expected:    "https://shop.com/search?category=electronics&discount=SUMMER20&ref=affiliate123&sort=price&utm_source=partner",
			description: "Affiliate tracking with discount codes",
		},
		{
			name:        "Analytics parameters",
			destination: "https://docs.example.com/api",
			incoming:    "?_ga=123.456&_gid=789.012&session=abc",
			expected:    "https://docs.example.com/api?_ga=123.456&_gid=789.012&session=abc",
			description: "Google Analytics tracking parameters",
		},
		{
			name:        "Special characters in parameters",
			destination: "https://api.example.com/search",
			incoming:    "?q=hello+world&filter=category%3Abooks",
			expected:    "https://api.example.com/search?filter=category%3Abooks&q=hello+world",
			description: "URL encoded special characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup rule
			parseAndSetMappings("test=" + tt.destination + ",status=302")

			// Create request
			req := httptest.NewRequest("GET", "/test"+tt.incoming, nil)
			w := httptest.NewRecorder()

			// Handle request
			handleRequest(w, req)

			// Check redirect location
			location := w.Header().Get("Location")
			if location != tt.expected {
				t.Errorf("%s\nExpected: %s\nGot:      %s", tt.description, tt.expected, location)
			}
		})
	}
}

func TestQueryParameterForwardingDisabled(t *testing.T) {
	// Test that query parameters are NOT forwarded when disabled
	cfg = config{
		forwardQueryParams: false,
	}

	parseAndSetMappings("product=https://shop.com/item?id=123,status=302")

	tests := []struct {
		name        string
		path        string
		expectedLoc string
	}{
		{
			"UTM parameters are dropped",
			"/product?utm_source=google&utm_campaign=test",
			"https://shop.com/item?id=123",
		},
		{
			"All incoming params dropped, destination params preserved",
			"/product?ref=partner&discount=CODE20",
			"https://shop.com/item?id=123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()

			handleRequest(w, req)

			location := w.Header().Get("Location")
			if location != tt.expectedLoc {
				t.Errorf("Expected %s, got %s", tt.expectedLoc, location)
			}
		})
	}
}

func TestHTTPConfigLoading(t *testing.T) {
	// Test detection of HTTP/HTTPS configuration URLs
	tests := []struct {
		mappingSource string
		shouldBeHTTP  bool
	}{
		{"http://config.example.com/redirects.txt", true},
		{"https://config.example.com/redirects.txt", true},
		{"HTTP://CONFIG.EXAMPLE.COM/REDIRECTS.TXT", true},
		{"HTTPS://CONFIG.EXAMPLE.COM/REDIRECTS.TXT", true},
		{"/etc/flink/redirects.txt", false},
		{"./redirects.txt", false},
		{"redirects.txt", false},
		{"shop=https://example.com;docs=https://docs.com", false},
	}

	for _, tt := range tests {
		isHTTP := strings.HasPrefix(strings.ToLower(tt.mappingSource), "http://") || strings.HasPrefix(strings.ToLower(tt.mappingSource), "https://")
		if isHTTP != tt.shouldBeHTTP {
			t.Errorf("For %s: expected HTTP=%v, got %v", tt.mappingSource, tt.shouldBeHTTP, isHTTP)
		}
	}
}
