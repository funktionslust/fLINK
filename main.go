// Package main implements a lightweight HTTP redirect service with dynamic rule loading.
// It supports both file-based and environment-based configuration with hot reloading.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
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

// redirectRule represents a single redirect mapping with destination URL and HTTP status code.
type redirectRule struct {
	url    string // Destination URL
	status int    // HTTP status code (301, 302, 303, 307, 308)
}

var (
	// rulesMu protects concurrent access to the rules map
	rulesMu sync.RWMutex
	// rules stores all active redirect mappings
	rules = map[string]redirectRule{}
)

// main initializes the redirect service and starts the HTTP server.
func main() {
	// Check for version flag
	if len(os.Args) > 1 && (os.Args[1] == "-version" || os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Printf("fLINK %s (commit: %s, built: %s)\n", version, commit, date)
		os.Exit(0)
	}

	printBanner()

	mappingSource := os.Getenv("REDIRECT_MAPPINGS")
	if mappingSource == "" {
		log.Fatal("REDIRECT_MAPPINGS environment variable is required")
	}

	// Determine if mapping source is a file or inline configuration
	if fileInfo, err := os.Stat(mappingSource); err == nil && !fileInfo.IsDir() {
		log.Printf("Watching file for changes: %s", mappingSource)
		loadFileMappings(mappingSource) // Initial load
		go watchFileForChanges(mappingSource, 5*time.Second)
	} else {
		log.Printf("Loading static mappings from environment variable")
		loadInlineMappings(mappingSource)
	}

	// Configure HTTP handlers
	http.HandleFunc("/", handleRequest)

	port := getEnv("PORT", "8080")
	log.Printf("Listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
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
	// Validate ID contains only safe characters
	if !isValidID(id) {
		logAccess(r, 400, time.Since(start), "error", "", "Invalid redirect ID")
		http.Error(w, "Invalid redirect ID", http.StatusBadRequest)
		return
	}

	// Thread-safe lookup of redirect rule
	rulesMu.RLock()
	rule, ok := rules[id]
	rulesMu.RUnlock()

	if !ok {
		logAccess(r, 404, time.Since(start), "error", "", "Redirect rule not found")
		http.NotFound(w, r)
		return
	}

	// Build destination URL with query parameters forwarded
	dest := rule.url
	if r.URL.RawQuery != "" {
		// Add query parameters to destination URL
		separator := "?"
		if strings.Contains(dest, "?") {
			separator = "&"
		}
		dest = dest + separator + r.URL.RawQuery
	}

	// Validate destination URL for basic security
	if !isValidURL(rule.url) {
		logAccess(r, 500, time.Since(start), "error", "", "Invalid destination URL")
		http.Error(w, "Invalid redirect destination", http.StatusInternalServerError)
		return
	}

	logAccess(r, rule.status, time.Since(start), "redirect", dest, "")
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
	rulesMu.RLock()
	_, ok := rules[id]
	rulesMu.RUnlock()

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

// parseAndSetMappings parses configuration data and atomically updates the active rules.
// Supports both newline and semicolon separated entries, with comment support.
func parseAndSetMappings(data string) {
	newRules := make(map[string]redirectRule)

	// Parse both newline and semicolon separated entries
	lines := strings.Split(data, "\n")
	for _, l := range lines {
		for _, entry := range strings.Split(l, ";") {
			entry = strings.TrimSpace(entry)
			// Skip empty lines and comments
			if entry == "" || strings.HasPrefix(entry, "#") {
				continue
			}
			parseMappingLine(entry, newRules)
		}
	}

	// Atomically replace all rules
	rulesMu.Lock()
	rules = newRules
	rulesMu.Unlock()

	// Log loaded rules
	log.Printf("Loaded %d redirect rule(s):", len(newRules))
	for id, rule := range newRules {
		log.Printf("  %s → %s (status: %d)", id, rule.url, rule.status)
	}
}

// parseMappingLine parses a single mapping line in the format "key=url" or "key=url,status=code".
func parseMappingLine(line string, rules map[string]redirectRule) {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		log.Printf("Invalid mapping format: %s", line)
		return
	}

	key := strings.TrimSpace(parts[0])
	val := strings.TrimSpace(parts[1])

	// Validate key is not empty and contains safe characters
	if key == "" || !isValidID(key) {
		log.Printf("Invalid mapping key: %s", key)
		return
	}

	// Default values
	url := val
	status := 302

	// Parse optional status code
	if strings.Contains(val, ",status=") {
		segments := strings.SplitN(val, ",status=", 2)
		url = strings.TrimSpace(segments[0])
		if s, err := parseStatusCode(strings.TrimSpace(segments[1])); err == nil {
			status = s
		} else {
			log.Printf("Invalid status code for %s: %v", key, err)
			return
		}
	}

	// Basic URL validation
	if url == "" {
		log.Printf("Empty URL for key %s", key)
		return
	}

	rules[key] = redirectRule{url: url, status: status}
}

// parseStatusCode validates and parses HTTP redirect status codes.
// Only allows standard redirect status codes for security and correctness.
func parseStatusCode(s string) (int, error) {
	switch s {
	case "301", "302", "303", "307", "308":
		var code int
		_, err := fmt.Sscanf(s, "%d", &code)
		return code, err
	default:
		return 0, fmt.Errorf("unsupported redirect status code: %s", s)
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
	// Check for reverse proxy headers first
	if host := r.Header.Get("X-Forwarded-Host"); host != "" {
		return host
	}
	if host := r.Header.Get("X-Original-Host"); host != "" {
		return host
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
	// Check for reverse proxy headers first
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
