// Package main implements a lightweight HTTP redirect service with dynamic rule loading.
// It supports both file-based and environment-based configuration with hot reloading.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"
)

// Build-time variables (set via -ldflags)
var (
	version = "latest"
	commit  = "unknown"
	date    = "unknown"
)

// Default trusted proxy ranges (RFC1918 private networks + loopback)
const defaultTrustedProxies = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128"

// redirectRule represents a single redirect mapping with destination URL and HTTP status code.
type redirectRule struct {
	url       string // Destination URL
	status    int    // HTTP status code (301, 302, 303, 307, 308)
	isPattern bool   // Whether this rule uses wildcard matching
	prefix    string // The prefix part before * (for pattern matching)
	path      string // Full path pattern (for sorting by specificity)
}

// BuildDestination constructs the final destination URL with wildcard replacement
func (r redirectRule) BuildDestination(suffix string) string {
	if !r.isPattern || suffix == "" {
		return r.url
	}
	if !strings.Contains(r.url, "*") {
		return r.url // Drop suffix if no wildcard in destination
	}
	// Normalize suffix to avoid double slashes
	if strings.HasSuffix(r.url, "/*") && strings.HasPrefix(suffix, "/") {
		suffix = suffix[1:]
	}
	return strings.Replace(r.url, "*", suffix, -1)
}

// RuleSet manages both exact and pattern-based redirect rules
type RuleSet struct {
	mu       sync.RWMutex
	exact    map[string]redirectRule
	patterns []redirectRule
}

// Match finds a matching rule for the given path
func (rs *RuleSet) Match(path string) (redirectRule, bool, string) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	// Check exact matches first
	if rule, ok := rs.exact[path]; ok {
		return rule, true, ""
	}

	// Check pattern rules
	fullPath := "/" + path
	for _, rule := range rs.patterns {
		if strings.HasPrefix(fullPath, rule.prefix) {
			suffix := strings.TrimPrefix(fullPath, rule.prefix)
			if rule.prefix == "/" {
				suffix = fullPath // For root wildcard, keep full path
			}
			return rule, true, suffix
		}
	}

	return redirectRule{}, false, ""
}

// Update atomically replaces all rules
func (rs *RuleSet) Update(exact map[string]redirectRule, patterns []redirectRule) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.exact = exact
	rs.patterns = patterns
}

// config holds all application configuration
type config struct {
	port               string
	mappingSource      string
	forwardQueryParams bool
	trustedProxies     string // Comma-separated CIDR ranges of trusted proxies
	matomoURL          string
	matomoToken        string
}

var (
	// ruleSet manages all redirect rules
	ruleSet = &RuleSet{
		exact: make(map[string]redirectRule),
	}
	// cfg holds the application configuration
	cfg config
	// trustedProxyChecker manages trusted proxy validation
	trustedProxyChecker struct {
		once sync.Once
		mu   sync.RWMutex
		nets []*net.IPNet
	}
)

// main initializes the redirect service and starts the HTTP server.
func main() {
	// Define command-line flags
	var (
		portFlag           = flag.String("port", "", "Server port")
		mappingsFlag       = flag.String("mappings", "", "File path, URL, or inline mappings")
		forwardParamsFlag  = flag.Bool("forward-query-params", true, "Forward query parameters to destination")
		trustedProxiesFlag = flag.String("trusted-proxies", "", "Comma-separated CIDR ranges of trusted proxies")
		matomoURLFlag      = flag.String("matomo-url", "", "Matomo analytics URL")
		matomoTokenFlag    = flag.String("matomo-token", "", "Matomo API token")
		versionFlag        = flag.Bool("version", false, "Show version information")
		helpFlag           = flag.Bool("help", false, "Show help message")
	)

	// Custom usage message
	flag.Usage = func() {
		printHelp()
	}

	// Parse flags
	flag.Parse()

	// Handle version and help flags
	if *helpFlag {
		printHelp()
		os.Exit(0)
	}

	if *versionFlag {
		fmt.Printf("fLINK %s (commit: %s, built: %s)\n", version, commit, date)
		os.Exit(0)
	}

	printBanner()

	// Load configuration (CLI flags override environment variables)
	cfg = loadConfig(*portFlag, *mappingsFlag, *forwardParamsFlag, *trustedProxiesFlag, *matomoURLFlag, *matomoTokenFlag)

	// Initialize tracking system with config
	initTracking(cfg)

	// Print configuration after all systems are initialized
	printConfig()

	// Initialize trusted proxy networks
	if err := initTrustedProxies(cfg.trustedProxies); err != nil {
		log.Printf("Warning: Failed to parse trusted proxies: %v", err)
	}

	// Determine mapping source type
	if strings.HasPrefix(cfg.mappingSource, "http://") || strings.HasPrefix(cfg.mappingSource, "https://") {
		log.Printf("Loading mappings from URL: %s", cfg.mappingSource)
		loadHTTPMappings(cfg.mappingSource) // Initial load
		go watchHTTPForChanges(cfg.mappingSource, 10*time.Minute)
	} else if fileInfo, err := os.Stat(cfg.mappingSource); err == nil && !fileInfo.IsDir() {
		log.Printf("Watching file for changes: %s", cfg.mappingSource)
		loadFileMappings(cfg.mappingSource) // Initial load
		go watchFileForChanges(cfg.mappingSource, 5*time.Second)
	} else {
		log.Printf("Loading static mappings from environment variable")
		loadInlineMappings(cfg.mappingSource)
	}

	// Configure HTTP handlers
	http.HandleFunc("/", handleRequest)

	log.Printf("Listening on :%s", cfg.port)
	log.Fatal(http.ListenAndServe(":"+cfg.port, nil))
}

// loadConfig loads configuration from CLI flags and environment variables
// CLI flags take precedence over environment variables
func loadConfig(portFlag, mappingsFlag string, forwardParamsFlag bool, trustedProxiesFlag, matomoURLFlag, matomoTokenFlag string) config {
	c := config{}

	// Port: CLI flag > env var > default
	if portFlag != "" {
		c.port = portFlag
	} else {
		c.port = getEnv("PORT", "8080")
	}

	// Mappings: CLI flag > env var
	if mappingsFlag != "" {
		c.mappingSource = mappingsFlag
	} else {
		c.mappingSource = os.Getenv("REDIRECT_MAPPINGS")
	}

	// Forward query params: CLI flag takes precedence if explicitly set
	// Note: flag.Bool always returns a value, so we need to check if it was actually set
	if flagWasSet("forward-query-params") {
		c.forwardQueryParams = forwardParamsFlag
	} else {
		c.forwardQueryParams = getEnvBool("FORWARD_QUERY_PARAMS", true)
	}

	// Trusted proxies: CLI flag takes precedence
	if trustedProxiesFlag != "" {
		c.trustedProxies = trustedProxiesFlag
	} else {
		c.trustedProxies = os.Getenv("TRUSTED_PROXIES")
		if c.trustedProxies == "" {
			// Default to common private network ranges
			c.trustedProxies = defaultTrustedProxies
		}
	}

	// Matomo URL: CLI flag takes precedence
	if matomoURLFlag != "" {
		c.matomoURL = matomoURLFlag
	} else {
		c.matomoURL = getEnvOrFile("MATOMO_URL")
	}

	// Matomo Token: CLI flag takes precedence
	if matomoTokenFlag != "" {
		c.matomoToken = matomoTokenFlag
	} else {
		c.matomoToken = getEnvOrFile("MATOMO_TOKEN")
	}

	if c.mappingSource == "" {
		log.Fatal("Redirect mappings are required. Use -mappings flag or REDIRECT_MAPPINGS environment variable")
	}

	return c
}

// flagWasSet checks if a flag was explicitly set on the command line
func flagWasSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// printConfig displays the current configuration
func printConfig() {
	log.Println("Configuration:")
	log.Printf("  Port: %s", cfg.port)
	log.Printf("  Forward Query Parameters: %v", cfg.forwardQueryParams)
	log.Printf("  Trusted Proxies: %s", cfg.trustedProxies)

	// Show tracking status
	if tracker != nil && tracker.IsEnabled() {
		log.Printf("  Analytics: %s enabled", tracker.Name())
	} else {
		log.Printf("  Analytics: disabled")
	}
}

// printHelp displays usage information
func printHelp() {
	fmt.Printf(`fLINK %s - Simple, Fast URL Redirector

USAGE:
  flink [options]

OPTIONS:
  -help                    Show this help message
  -version                 Show version information
  -port PORT               Server port (default: 8080)
  -mappings PATH|URL|DATA  File path, URL, or inline mappings (required)
  -forward-query-params    Forward query parameters to destination (default: true)
  -trusted-proxies CIDRS   Comma-separated CIDR ranges of trusted proxies
  -matomo-url URL          Matomo analytics URL
  -matomo-token TOKEN      Matomo API token

ENVIRONMENT VARIABLES:
  REDIRECT_MAPPINGS        File path, URL, or inline mappings
  PORT                     Server port
  FORWARD_QUERY_PARAMS     Forward query parameters to destination
  TRUSTED_PROXIES          Comma-separated CIDR ranges of trusted proxies
  MATOMO_URL               Matomo analytics URL (optional)
  MATOMO_TOKEN             Matomo API token (optional)

All environment variables support _FILE suffix for Docker secrets.
CLI flags take precedence over environment variables.

EXAMPLES:
  # Using CLI flags
  flink -mappings /etc/flink/redirects.txt -port 8080
  
  # Inline mappings via CLI
  flink -mappings "shop=https://store.com;docs=https://docs.com"
  
  # Remote configuration via CLI
  flink -mappings https://config.example.com/redirects.txt
  
  # Disable query parameter forwarding
  flink -mappings redirects.txt -forward-query-params=false

  # With Matomo analytics
  flink -mappings redirects.txt -matomo-url https://analytics.example.com -matomo-token your-token

  # Custom trusted proxies
  flink -mappings redirects.txt -trusted-proxies "10.0.0.0/8,192.168.1.0/24"

  # Using environment variables
  REDIRECT_MAPPINGS=/etc/flink/redirects.txt PORT=8080 flink

For more information, visit: https://github.com/funktionslust/fLINK
`, version)
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

// getEnvBool reads a boolean environment variable with a default value
func getEnvBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value == "true" || value == "1" || value == "yes"
}

// initTrustedProxies initializes trusted proxy validation (called once at startup)
func initTrustedProxies(ranges string) error {
	var err error
	trustedProxyChecker.once.Do(func() {
		err = parseTrustedProxies(ranges)
	})
	return err
}

// parseTrustedProxies parses CIDR ranges for trusted proxy validation
func parseTrustedProxies(ranges string) error {
	var nets []*net.IPNet

	if ranges == "" {
		return nil
	}

	for _, cidr := range strings.Split(ranges, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try parsing as single IP
			ip := net.ParseIP(cidr)
			if ip == nil {
				return fmt.Errorf("invalid CIDR or IP: %s", cidr)
			}
			// Convert single IP to CIDR
			if ip.To4() != nil {
				_, ipNet, _ = net.ParseCIDR(cidr + "/32")
			} else {
				_, ipNet, _ = net.ParseCIDR(cidr + "/128")
			}
		}
		nets = append(nets, ipNet)
	}

	trustedProxyChecker.mu.Lock()
	trustedProxyChecker.nets = nets
	trustedProxyChecker.mu.Unlock()

	return nil
}

// isTrustedProxy checks if the request comes from a trusted proxy
func isTrustedProxy(remoteAddr string) bool {
	trustedProxyChecker.mu.RLock()
	nets := trustedProxyChecker.nets
	trustedProxyChecker.mu.RUnlock()

	if len(nets) == 0 {
		return false
	}

	// Extract IP from remote address (remove port)
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr // Fallback if no port
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	for _, trustedNet := range nets {
		if trustedNet.Contains(ip) {
			return true
		}
	}
	return false
}

// setCommonHeaders adds standard security and informational headers to all responses.
func setCommonHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Powered-By", "fLINK by Funktionslust GmbH")
	w.Header().Set("Server", fmt.Sprintf("fLINK/%s", version))
}

// handleRequest routes requests to either QR code generation or redirect functionality.
func handleRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Set common headers for all responses
	setCommonHeaders(w)

	// Only allow GET and HEAD requests for security
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		logAccess(r, 405, time.Since(start), "error", "", "Method not allowed")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract path from URL
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		logAccess(r, 404, time.Since(start), "error", "", "Empty path")
		http.NotFound(w, r)
		return
	}

	// Check if this is a QR code request
	if strings.HasSuffix(path, "/qr") {
		handleQRCode(w, r, strings.TrimSuffix(path, "/qr"), start)
		return
	}

	// Handle regular redirect
	handleRedirect(w, r, path, start)
}

// handleRedirect processes redirect requests based on configured rules.
func handleRedirect(w http.ResponseWriter, r *http.Request, id string, start time.Time) {
	// Validate path contains only safe characters
	if !isValidPathSegment(id) {
		logAccess(r, 400, time.Since(start), "error", "", "Invalid redirect path")
		http.Error(w, "Invalid redirect path", http.StatusBadRequest)
		return
	}

	// Find matching rule using RuleSet
	rule, ok, suffix := ruleSet.Match(id)
	if !ok {
		logAccess(r, 404, time.Since(start), "error", "", "Redirect rule not found")
		http.NotFound(w, r)
		return
	}

	// Build destination URL with wildcard suffix replacement
	dest := rule.BuildDestination(suffix)

	// Handle query parameter forwarding
	if cfg.forwardQueryParams && r.URL.RawQuery != "" {
		// Parse destination URL properly
		destURL, err := url.Parse(dest)
		if err != nil {
			logAccess(r, 500, time.Since(start), "error", "", "Invalid destination URL")
			http.Error(w, "Invalid redirect destination", http.StatusInternalServerError)
			return
		}

		// Parse incoming query parameters
		incomingParams, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			logAccess(r, 400, time.Since(start), "error", "", "Invalid query parameters")
			http.Error(w, "Invalid query parameters", http.StatusBadRequest)
			return
		}

		// Merge query parameters (incoming params override existing ones)
		existingParams := destURL.Query()
		for key, values := range incomingParams {
			for _, value := range values {
				existingParams.Add(key, value)
			}
		}

		// Update the URL with merged parameters
		destURL.RawQuery = existingParams.Encode()
		dest = destURL.String()
	}

	// Validate destination URL for basic security
	if !isValidURL(rule.url) {
		logAccess(r, 500, time.Since(start), "error", "", "Invalid destination URL")
		http.Error(w, "Invalid redirect destination", http.StatusInternalServerError)
		return
	}

	logAccess(r, rule.status, time.Since(start), "redirect", dest, "")

	// Track redirect event
	trackEvent(r, "redirect", id, dest)

	// Perform the redirect
	// Note: HTTP redirects naturally preserve the original referer (not the redirect server)
	// The preserveReferer option would only be needed if we wanted to CHANGE this behavior
	http.Redirect(w, r, dest, rule.status)
}

// handleQRCode generates and serves QR codes for short URLs.
func handleQRCode(w http.ResponseWriter, r *http.Request, id string, start time.Time) {
	// Validate ID contains only safe characters
	if !isValidID(id) {
		logAccess(r, 400, time.Since(start), "error", "", "Invalid redirect ID")
		http.Error(w, "Invalid redirect ID", http.StatusBadRequest)
		return
	}

	// Check if redirect rule exists
	_, ok, _ := ruleSet.Match(id)
	if !ok {
		logAccess(r, 404, time.Since(start), "error", "", "QR code rule not found")
		http.NotFound(w, r)
		return
	}

	// Get the full URL for the QR code including prefix
	hostname := getHostname(r)
	prefix := getPathPrefix(r)
	shortURL := fmt.Sprintf("https://%s%s/%s", hostname, prefix, id)

	// Generate QR code
	qrCode, err := qrcode.Encode(shortURL, qrcode.High, 512)
	if err != nil {
		logAccess(r, 500, time.Since(start), "error", "", fmt.Sprintf("QR generation failed: %v", err))
		http.Error(w, "Failed to generate QR code", http.StatusInternalServerError)
		return
	}

	// Set appropriate headers
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour

	// Write QR code image
	w.Write(qrCode)
	logAccess(r, 200, time.Since(start), "qr", shortURL, "")
}

// loadFileMappings reads redirect rules from a file and updates the active configuration.
func loadFileMappings(path string) {
	content, err := os.ReadFile(path)
	if err != nil {
		log.Printf("Error reading mapping file: %v", err)
		return
	}
	parseAndSetMappings(string(content))
}

// watchFileForChanges monitors a file for modifications and reloads mappings when changes are detected.
func watchFileForChanges(path string, interval time.Duration) {
	// Get initial modification time
	stat, err := os.Stat(path)
	if err != nil {
		log.Printf("Failed to stat mapping file: %v", err)
		return
	}
	lastMod := stat.ModTime()

	for {
		time.Sleep(interval)
		stat, err := os.Stat(path)
		if err != nil {
			log.Printf("Failed to stat mapping file: %v", err)
			continue
		}
		if stat.ModTime().After(lastMod) {
			lastMod = stat.ModTime()
			log.Printf("Detected change in %s, reloading...", path)
			loadFileMappings(path)
		}
	}
}

// loadInlineMappings parses redirect rules from a string (typically from environment variable).
func loadInlineMappings(data string) {
	parseAndSetMappings(data)
}

// loadHTTPMappings fetches redirect rules from an HTTP/HTTPS URL.
func loadHTTPMappings(url string) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		log.Printf("Error fetching mappings from URL: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Error fetching mappings: HTTP %d", resp.StatusCode)
		return
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading mappings response: %v", err)
		return
	}

	parseAndSetMappings(string(content))
}

// watchHTTPForChanges periodically fetches mappings from an HTTP/HTTPS URL.
func watchHTTPForChanges(url string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		log.Printf("Refreshing mappings from URL: %s", url)
		loadHTTPMappings(url)
	}
}

// parseAndSetMappings parses configuration data and atomically updates the active rules.
// Supports both newline and semicolon separated entries, with comment support.
func parseAndSetMappings(data string) {
	newRules := make(map[string]redirectRule)
	var newPatternRules []redirectRule

	// Parse both newline and semicolon separated entries
	lines := strings.Split(data, "\n")
	for _, l := range lines {
		for _, entry := range strings.Split(l, ";") {
			entry = strings.TrimSpace(entry)
			// Skip empty lines and comments
			if entry == "" || strings.HasPrefix(entry, "#") {
				continue
			}
			rule, ok := parseMappingLine(entry)
			if !ok {
				continue // Skip invalid rules
			}
			if rule.isPattern {
				newPatternRules = append(newPatternRules, rule)
			} else {
				newRules[rule.path] = rule
			}
		}
	}

	// Sort pattern rules by specificity (longest prefix first)
	sort.Slice(newPatternRules, func(i, j int) bool {
		// Longer prefixes match first (more specific)
		if len(newPatternRules[i].prefix) != len(newPatternRules[j].prefix) {
			return len(newPatternRules[i].prefix) > len(newPatternRules[j].prefix)
		}
		// If same length, alphabetical order for consistency
		return newPatternRules[i].prefix < newPatternRules[j].prefix
	})

	// Atomically update all rules
	ruleSet.Update(newRules, newPatternRules)

	// Log loaded rules
	totalRules := len(newRules) + len(newPatternRules)
	log.Printf("Loaded %d redirect rule(s) (%d exact, %d patterns):", totalRules, len(newRules), len(newPatternRules))
	for id, rule := range newRules {
		log.Printf("  %s → %s (status: %d)", id, rule.url, rule.status)
	}
	for _, rule := range newPatternRules {
		log.Printf("  %s → %s (status: %d) [pattern]", rule.path, rule.url, rule.status)
	}
}

// parseMappingLine parses a single mapping line in the format "key=url" or "key=url,status=code".
// Supports wildcard patterns with * for suffix matching.
// Returns the parsed rule and whether it's a pattern rule.
func parseMappingLine(line string) (redirectRule, bool) {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		log.Printf("Invalid mapping format: %s", line)
		return redirectRule{}, false
	}

	key := strings.TrimSpace(parts[0])
	val := strings.TrimSpace(parts[1])

	// Check if this is a wildcard pattern
	isPattern := strings.Contains(key, "*")
	prefix := ""

	if isPattern {
		// For wildcard patterns, extract the prefix
		if key == "*" || key == "/*" {
			prefix = "/" // Root wildcard catches everything
		} else if strings.HasSuffix(key, "/*") {
			prefix = "/" + strings.TrimSuffix(key, "*") // Ensure leading slash for path patterns
		} else {
			log.Printf("Invalid wildcard pattern: %s (wildcards only supported at end of path)", key)
			return redirectRule{}, false
		}
	} else {
		// Validate exact match key contains safe characters
		if key == "" || !isValidPathSegment(key) {
			log.Printf("Invalid mapping key: %s", key)
			return redirectRule{}, false
		}
	}

	// Default values
	url := val
	status := 302

	// Parse optional status code (supports both ,status= and named aliases)
	if idx := strings.LastIndex(val, ","); idx != -1 {
		possibleStatus := strings.TrimSpace(val[idx+1:])
		// Check if it's a status directive (TrimPrefix is safe even if prefix doesn't exist)
		possibleStatus = strings.TrimPrefix(possibleStatus, "status=")
		// Try to parse as status code or alias
		if s, err := parseStatusCode(possibleStatus); err == nil {
			status = s
			url = strings.TrimSpace(val[:idx])
		}
	}

	// Basic URL validation
	if url == "" {
		log.Printf("Empty URL for key %s", key)
		return redirectRule{}, false
	}

	// Create the redirect rule
	rule := redirectRule{
		url:       url,
		status:    status,
		isPattern: isPattern,
		prefix:    prefix,
		path:      key,
	}

	return rule, true
}

// isValidPathSegment checks if a path segment is safe to use
func isValidPathSegment(path string) bool {
	if len(path) == 0 || len(path) > 2048 {
		return false
	}

	// Reject path traversal attempts
	if strings.Contains(path, "..") {
		return false
	}

	// Reject null bytes
	if strings.Contains(path, "\x00") {
		return false
	}

	// Check if path needs escaping (except for slashes which are allowed)
	escaped := url.PathEscape(path)
	unescapedSlashes := strings.ReplaceAll(escaped, "%2F", "/")

	return unescapedSlashes == path
}

// parseStatusCode validates and parses HTTP redirect status codes.
// Supports both numeric codes and named aliases for better readability.
func parseStatusCode(s string) (int, error) {
	switch s {
	case "301", "permanent":
		return 301, nil
	case "302", "temporary", "temp":
		return 302, nil
	case "303", "see-other":
		return 303, nil
	case "307", "temporary-strict":
		return 307, nil
	case "308", "permanent-strict":
		return 308, nil
	default:
		return 0, fmt.Errorf("unsupported redirect status code: %s (use: permanent, temporary, permanent-strict, temporary-strict, or 301-308)", s)
	}
}

// isValidID checks if an ID contains only safe characters (alphanumeric, hyphens, underscores).
func isValidID(id string) bool {
	if len(id) == 0 || len(id) > 256 {
		return false
	}
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// isValidURL performs basic URL validation to prevent obvious security issues.
func isValidURL(url string) bool {
	if len(url) == 0 || len(url) > 2048 {
		return false
	}
	// Must start with http:// or https://
	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
}

// getHostname extracts hostname from request, considering reverse proxy headers.
func getHostname(r *http.Request) string {
	// Only trust proxy headers if request is from a trusted proxy
	if isTrustedProxy(r.RemoteAddr) {
		if host := r.Header.Get("X-Forwarded-Host"); host != "" {
			return host
		}
		if host := r.Header.Get("X-Original-Host"); host != "" {
			return host
		}
	}
	// Fall back to Host header
	if host := r.Host; host != "" {
		return host
	}
	// Final fallback
	return "localhost:8080"
}

// getPathPrefix extracts the original path prefix from reverse proxy headers.
func getPathPrefix(r *http.Request) string {
	// Only trust proxy headers if request is from a trusted proxy
	if isTrustedProxy(r.RemoteAddr) {
		// Check for X-Forwarded-Prefix header (used by many reverse proxies)
		if prefix := r.Header.Get("X-Forwarded-Prefix"); prefix != "" {
			return prefix
		}
		// Check for X-Forwarded-Path which some proxies use
		if path := r.Header.Get("X-Forwarded-Path"); path != "" {
			// Extract just the prefix part if the full path is provided
			if idx := strings.LastIndex(path, "/"); idx > 0 {
				return path[:idx]
			}
		}
	}
	return ""
}

// logAccess writes structured access logs.
func logAccess(r *http.Request, status int, duration time.Duration, logType, destination, errorMsg string) {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	remoteAddr := getRemoteAddr(r)

	// Build log message based on type
	var logMsg string
	switch logType {
	case "redirect":
		logMsg = fmt.Sprintf("[%s] %s %s %s → %s (%d) %s",
			timestamp, remoteAddr, r.Method, r.URL.Path, destination, status, duration)
	case "qr":
		logMsg = fmt.Sprintf("[%s] %s %s %s → QR:%s (%d) %s",
			timestamp, remoteAddr, r.Method, r.URL.Path, destination, status, duration)
	case "error":
		logMsg = fmt.Sprintf("[%s] %s %s %s ERROR: %s (%d) %s",
			timestamp, remoteAddr, r.Method, r.URL.Path, errorMsg, status, duration)
	default:
		logMsg = fmt.Sprintf("[%s] %s %s %s (%d) %s",
			timestamp, remoteAddr, r.Method, r.URL.Path, status, duration)
	}

	log.Println(logMsg)
}

// getRemoteAddr extracts the real client IP considering reverse proxy headers.
func getRemoteAddr(r *http.Request) string {
	// Only trust proxy headers if request is from a trusted proxy
	if isTrustedProxy(r.RemoteAddr) {
		if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
			// X-Forwarded-For can contain multiple IPs, take the first one
			if idx := strings.Index(ip, ","); idx != -1 {
				return strings.TrimSpace(ip[:idx])
			}
			return ip
		}
		if ip := r.Header.Get("X-Real-IP"); ip != "" {
			return ip
		}
	}
	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// printBanner displays the application banner with company attribution.
func printBanner() {
	logo := `
    ██████  █████       █████ ██████   █████ █████   ████
   ███░░███░░███       ░░███ ░░██████ ░░███ ░░███   ███░ 
  ░███ ░░░  ░███        ░███  ░███░███ ░███  ░███  ███   
 ███████    ░███        ░███  ░███░░███░███  ░███████    
░░░███░     ░███        ░███  ░███ ░░██████  ░███░░███   
  ░███      ░███      █ ░███  ░███  ░░█████  ░███ ░░███  
  █████     ███████████ █████ █████  ░░█████ █████ ░░████
 ░░░░░     ░░░░░░░░░░░ ░░░░░ ░░░░░    ░░░░░ ░░░░░   ░░░░ `

	fmt.Println("\033[36m" + logo + "\033[0m")

	credits := fmt.Sprintf(`
 Lightweight HTTP Redirect Service v%s
 Developed by Funktionslust GmbH
 https://funktionslust.digital`, version)
	fmt.Println(credits)
}

// getEnv retrieves an environment variable with a fallback default value.
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
