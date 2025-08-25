package tracking

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// MatomoSite represents a site configured in Matomo
type matomoSite struct {
	IDSite  int      `json:"idsite"`
	Name    string   `json:"name"`
	MainURL string   `json:"main_url"`
	URLs    []string `json:"urls,omitempty"`
}

// MatomoTracker implements the Tracker interface for Matomo analytics.
// It supports automatic multi-site tracking based on destination domains.
type MatomoTracker struct {
	url     string
	token   string
	enabled bool
	sites   []matomoSite
	sitesMu sync.RWMutex
}

// NewMatomoTracker creates a new Matomo tracker with the given configuration
func NewMatomoTracker(matomoURL, token string) *MatomoTracker {
	tracker := &MatomoTracker{
		url:   strings.TrimSuffix(matomoURL, "/"),
		token: token,
		sites: []matomoSite{},
	}

	if tracker.url == "" || tracker.token == "" {
		return tracker
	}

	tracker.enabled = true
	log.Printf("Matomo tracking enabled with automatic site matching: %s", tracker.url)

	// Load sites initially
	if err := tracker.loadSites(); err != nil {
		log.Printf("Warning: Failed to load Matomo sites: %v", err)
		tracker.enabled = false
		return tracker
	}

	// Refresh sites periodically
	go tracker.refreshSitesPeriodically()

	return tracker
}

// Name returns the tracker name
func (m *MatomoTracker) Name() string {
	return "Matomo"
}

// IsEnabled returns whether Matomo tracking is enabled
func (m *MatomoTracker) IsEnabled() bool {
	return m.enabled
}

// TrackEvent sends an event to Matomo for the appropriate site
func (m *MatomoTracker) TrackEvent(data EventData, category, action, name string) {
	if !m.enabled {
		return
	}

	// Find matching site based on destination URL
	matchingSite := m.findMatchingSite(name)
	if matchingSite == nil {
		// No matching site found, skip tracking silently
		return
	}

	siteID := fmt.Sprintf("%d", matchingSite.IDSite)

	// Build tracking parameters
	params := url.Values{}
	params.Set("idsite", siteID)
	params.Set("rec", "1")
	params.Set("apiv", "1")
	params.Set("rand", fmt.Sprintf("%d", rand.Int()))

	// Event tracking parameters
	params.Set("e_c", category)
	params.Set("e_a", action)
	params.Set("e_n", name)

	// Use destination URL as the tracked page
	params.Set("url", name)

	// Forward all query parameters with proper Matomo mappings
	for key, values := range data.QueryParams {
		if len(values) > 0 {
			switch key {
			case "utm_campaign":
				params.Set("_rcn", values[0]) // Campaign name
			case "utm_medium":
				// Also contributes to campaign name in basic Matomo
				if params.Get("_rcn") == "" {
					params.Set("_rcn", values[0])
				}
			case "utm_source":
				// Also contributes to campaign name in basic Matomo
				if params.Get("_rcn") == "" {
					params.Set("_rcn", values[0])
				}
			case "utm_term":
				params.Set("_rck", values[0]) // Campaign keyword
			case "utm_content":
				// Pass through for plugins that support it
				params.Set("utm_content", values[0])
			case "gclid", "fbclid", "msclkid":
				// Preserve click IDs for conversion tracking
				params.Set(key, values[0])
			default:
				// Pass through all other parameters
				params.Set(key, values[0])
			}
		}
	}

	// User information - already cleaned by main package
	params.Set("cip", data.RemoteAddr)

	if data.UserAgent != "" {
		params.Set("ua", data.UserAgent)
	}

	if data.Referer != "" {
		params.Set("urlref", data.Referer)
	}

	if data.Language != "" {
		params.Set("lang", data.Language)
	}

	if m.token != "" {
		params.Set("token_auth", m.token)
	}

	// Send tracking request asynchronously
	go m.sendTrackingRequest(params, siteID)
}

func (m *MatomoTracker) sendTrackingRequest(params url.Values, siteID string) {
	trackingURL := fmt.Sprintf("%s/matomo.php", m.url)

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.PostForm(trackingURL, params)
	if err != nil {
		log.Printf("Matomo tracking error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		log.Printf("Matomo tracking error: unexpected status %d for site %s", resp.StatusCode, siteID)
	}
}

func (m *MatomoTracker) loadSites() error {
	apiURL := fmt.Sprintf("%s/index.php?module=API&method=SitesManager.getAllSites&format=JSON", m.url)

	formData := url.Values{}
	formData.Set("token_auth", m.token)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.PostForm(apiURL, formData)
	if err != nil {
		return fmt.Errorf("failed to fetch sites: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var sites []matomoSite
	if err := json.NewDecoder(resp.Body).Decode(&sites); err != nil {
		return fmt.Errorf("failed to decode sites: %w", err)
	}

	// Check if sites have changed
	m.sitesMu.RLock()
	oldCount := len(m.sites)
	changed := oldCount != len(sites)
	if !changed {
		for i, site := range sites {
			if i >= oldCount || m.sites[i].IDSite != site.IDSite ||
				m.sites[i].MainURL != site.MainURL || m.sites[i].Name != site.Name {
				changed = true
				break
			}
		}
	}
	m.sitesMu.RUnlock()

	// Update sites
	m.sitesMu.Lock()
	m.sites = sites
	m.sitesMu.Unlock()

	// Only log if this is the initial load or if sites have changed
	if oldCount == 0 || changed {
		log.Printf("Loaded %d Matomo sites for automatic matching", len(sites))
		for _, site := range sites {
			log.Printf("  Site %d: %s (%s)", site.IDSite, site.Name, site.MainURL)
		}
	}

	return nil
}

func (m *MatomoTracker) refreshSitesPeriodically() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		if err := m.loadSites(); err != nil {
			log.Printf("Error refreshing Matomo sites: %v", err)
		}
	}
}

func (m *MatomoTracker) findMatchingSite(destinationURL string) *matomoSite {
	m.sitesMu.RLock()
	defer m.sitesMu.RUnlock()

	parsedURL, err := url.Parse(destinationURL)
	if err != nil {
		return nil
	}

	destDomain := normalizeDomain(parsedURL.Host)

	for _, site := range m.sites {
		// Check main URL
		if siteURL, err := url.Parse(site.MainURL); err == nil {
			siteDomain := normalizeDomain(siteURL.Host)
			if siteDomain == destDomain {
				return &site
			}
		}

		// Check additional URLs
		for _, additionalURL := range site.URLs {
			if siteURL, err := url.Parse(additionalURL); err == nil {
				siteDomain := normalizeDomain(siteURL.Host)
				if siteDomain == destDomain {
					return &site
				}
			}
		}
	}

	return nil
}

func normalizeDomain(host string) string {
	host = strings.ToLower(host)
	return strings.TrimPrefix(host, "www.")
}
