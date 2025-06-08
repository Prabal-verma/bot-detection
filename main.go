package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RequestInfo stores detailed information about requests
type RequestInfo struct {
	Count         int
	FirstSeen     time.Time
	LastSeen      time.Time
	UserAgent     string
	RequestPaths  []string
	RequestTimes  []time.Time
	IsBot         bool
	BotConfidence float64
	Reasons       []string
	// New fields for enhanced detection
	HeaderIntegrity   map[string]bool
	TLSFingerprint    string
	TimeOnSite        time.Duration
	JSChallengePassed bool
	BehaviorData      *BehaviorData
	PathRequestCounts map[string]int
	LastCaptchaCheck  time.Time
	CaptchaVerified   bool
	DNSInfo           *DNSInfo
	IPReputation      *IPReputation
}

// BehaviorData stores user behavior metrics
type BehaviorData struct {
	MouseMovements    int
	ScrollEvents      int
	KeyPresses        int
	LastActivity      time.Time
	AverageTimeOnPage time.Duration
}

// DNSInfo stores DNS lookup results
type DNSInfo struct {
	Hostnames   []string
	LastChecked time.Time
	IsKnownBot  bool
}

// IPReputation stores IP reputation data
type IPReputation struct {
	Score         float64
	LastChecked   time.Time
	IsBlacklisted bool
	ThreatLevel   string
}

// BotDetectionConfig holds configuration for bot detection
type BotDetectionConfig struct {
	MaxRequestsPerMinute int
	MaxRequestsPerHour   int
	SuspiciousUserAgents []string
	WindowSize           time.Duration
	// New configuration options
	RequiredHeaders      []string
	HoneypotPaths        []string
	CaptchaThreshold     float64
	MinTimeOnSite        time.Duration
	MaxRequestsPerPath   int
	IPReputationAPIKey   string
	EnableTLSFingerprint bool
	EnableDNSLookup      bool
}

// Global variables
var (
	requests = make(map[string]*RequestInfo)
	mu       sync.Mutex
	config   = BotDetectionConfig{
		MaxRequestsPerMinute: 100,
		MaxRequestsPerHour:   1000,
		SuspiciousUserAgents: []string{
			"bot", "crawler", "spider", "scraper", "python-requests",
			"curl", "wget", "apache-httpclient", "java-http-client",
		},
		WindowSize: time.Minute,
		RequiredHeaders: []string{
			"Accept", "Accept-Encoding", "Accept-Language", "Connection",
			"Referer", "DNT", "Sec-Fetch-Dest", "Sec-Fetch-Mode",
			"Sec-Fetch-Site", "Sec-Fetch-User",
		},
		HoneypotPaths: []string{
			"/fake-login", "/fake-register", "/fake-checkout",
			"/admin-panel", "/wp-login.php",
		},
		CaptchaThreshold:     0.4,
		MinTimeOnSite:        time.Second * 3,
		MaxRequestsPerPath:   50,
		EnableTLSFingerprint: true,
		EnableDNSLookup:      true,
	}
)

// analyzeRequest performs detailed bot detection analysis
func analyzeRequest(ip string, r *http.Request) *RequestInfo {
	now := time.Now()
	info, exists := requests[ip]

	if !exists {
		info = &RequestInfo{
			FirstSeen:    now,
			LastSeen:     now,
			UserAgent:    r.UserAgent(),
			RequestPaths: []string{r.URL.Path},
			RequestTimes: []time.Time{now},
			Reasons:      []string{},
		}
		requests[ip] = info
		return info
	}

	// Update request info
	info.LastSeen = now
	info.Count++
	info.RequestPaths = append(info.RequestPaths, r.URL.Path)
	info.RequestTimes = append(info.RequestTimes, now)

	// Clean up old requests
	cleanupOldRequests(info)

	// Perform bot detection checks
	performBotChecks(info, r)

	return info
}

// cleanupOldRequests removes requests older than the window size
func cleanupOldRequests(info *RequestInfo) {
	now := time.Now()
	windowStart := now.Add(-config.WindowSize)

	// Clean up request times
	var newTimes []time.Time
	for _, t := range info.RequestTimes {
		if t.After(windowStart) {
			newTimes = append(newTimes, t)
		}
	}
	info.RequestTimes = newTimes

	// Update count
	info.Count = len(newTimes)
}

// performBotChecks runs various bot detection checks
func performBotChecks(info *RequestInfo, r *http.Request) {
	info.Reasons = []string{}
	info.BotConfidence = 0.0

	// 1. Check request frequency
	if info.Count > config.MaxRequestsPerMinute {
		info.Reasons = append(info.Reasons, "high request frequency")
		info.BotConfidence += 0.4
	}

	// 2. Check user agent
	userAgent := strings.ToLower(r.UserAgent())
	for _, suspicious := range config.SuspiciousUserAgents {
		if strings.Contains(userAgent, suspicious) {
			info.Reasons = append(info.Reasons, "suspicious user agent")
			info.BotConfidence += 0.3
			break
		}
	}

	// 3. Header Integrity Check
	missingHeaders := []string{}
	for _, header := range config.RequiredHeaders {
		if r.Header.Get(header) == "" {
			missingHeaders = append(missingHeaders, header)
		}
	}
	if len(missingHeaders) > 0 {
		info.Reasons = append(info.Reasons, "missing common headers: "+strings.Join(missingHeaders, ", "))
		info.BotConfidence += 0.2
	}

	// 4. TLS Fingerprint Check
	if config.EnableTLSFingerprint {
		tlsFingerprint := r.Header.Get("Cf-Tls-Fingerprint")
		if tlsFingerprint != "" {
			info.TLSFingerprint = tlsFingerprint
			// Add logic to check against known bot fingerprints
			if isKnownBotFingerprint(tlsFingerprint) {
				info.Reasons = append(info.Reasons, "suspicious TLS fingerprint")
				info.BotConfidence += 0.3
			}
		}
	}

	// 5. Time-on-Site Check
	if info.TimeOnSite < config.MinTimeOnSite {
		info.Reasons = append(info.Reasons, "suspiciously low time on site")
		info.BotConfidence += 0.2
	}

	// 6. JavaScript Challenge Check
	if !info.JSChallengePassed {
		info.Reasons = append(info.Reasons, "failed JavaScript challenge")
		info.BotConfidence += 0.4
	}

	// 7. Behavior Analysis
	if info.BehaviorData != nil {
		if info.BehaviorData.MouseMovements == 0 && info.BehaviorData.ScrollEvents == 0 {
			info.Reasons = append(info.Reasons, "no user behavior detected")
			info.BotConfidence += 0.3
		}
	}

	// 8. Path-based Rate Limiting
	path := r.URL.Path
	if count, exists := info.PathRequestCounts[path]; exists && count > config.MaxRequestsPerPath {
		info.Reasons = append(info.Reasons, "excessive requests to path: "+path)
		info.BotConfidence += 0.3
	}

	// 9. Honeypot Check
	for _, honeypotPath := range config.HoneypotPaths {
		if strings.Contains(path, honeypotPath) {
			info.Reasons = append(info.Reasons, "triggered honeypot")
			info.BotConfidence += 0.5
			break
		}
	}

	// 10. DNS Lookup Check
	if config.EnableDNSLookup && info.DNSInfo != nil {
		if info.DNSInfo.IsKnownBot {
			info.Reasons = append(info.Reasons, "known bot IP")
			info.BotConfidence += 0.4
		}
	}

	// 11. IP Reputation Check
	if info.IPReputation != nil {
		if info.IPReputation.IsBlacklisted {
			info.Reasons = append(info.Reasons, "blacklisted IP")
			info.BotConfidence += 0.5
		}
		if info.IPReputation.Score > 0.7 {
			info.Reasons = append(info.Reasons, "high risk IP")
			info.BotConfidence += 0.3
		}
	}

	// Determine if it's a bot based on confidence
	info.IsBot = info.BotConfidence >= 0.5
}

// isKnownBotFingerprint checks if a TLS fingerprint matches known bot patterns
func isKnownBotFingerprint(fingerprint string) bool {
	// Add your known bot fingerprint patterns here
	knownBotPatterns := []string{
		"python-requests",
		"curl",
		"wget",
		"java-http-client",
	}

	for _, pattern := range knownBotPatterns {
		if strings.Contains(strings.ToLower(fingerprint), pattern) {
			return true
		}
	}
	return false
}

// botDetectionHandler handles incoming requests
func botDetectionHandler(w http.ResponseWriter, r *http.Request) {
	ip := getIP(r)

	mu.Lock()
	info := analyzeRequest(ip, r)
	mu.Unlock()

	response := map[string]interface{}{
		"ip":             ip,
		"request_count":  info.Count,
		"is_bot":         info.IsBot,
		"bot_confidence": info.BotConfidence,
		"reasons":        info.Reasons,
		"first_seen":     info.FirstSeen,
		"last_seen":      info.LastSeen,
		"user_agent":     info.UserAgent,
		"unique_paths":   len(info.RequestPaths),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// getIP extracts IP address from request
func getIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	return ip
}

// Add this new middleware function
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Call the next handler
		next(w, r)
	}
}

func startFrontendServer() {
	fs := http.FileServer(http.Dir("."))
	http.Handle("/", fs)

	log.Println("🌐 Frontend server running at http://localhost:3000")
	go http.ListenAndServe(":3000", nil)
}

// jsChallengeHandler handles JavaScript challenge verification
func jsChallengeHandler(w http.ResponseWriter, r *http.Request) {
	ip := getIP(r)

	mu.Lock()
	info, exists := requests[ip]
	if !exists {
		info = &RequestInfo{
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
		requests[ip] = info
	}
	info.JSChallengePassed = true
	mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "JavaScript challenge passed",
	})
}

// behaviorTrackingHandler handles user behavior data
func behaviorTrackingHandler(w http.ResponseWriter, r *http.Request) {
	ip := getIP(r)

	var behaviorData BehaviorData
	if err := json.NewDecoder(r.Body).Decode(&behaviorData); err != nil {
		http.Error(w, "Invalid behavior data", http.StatusBadRequest)
		return
	}

	mu.Lock()
	info, exists := requests[ip]
	if !exists {
		info = &RequestInfo{
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
		requests[ip] = info
	}
	info.BehaviorData = &behaviorData
	mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Behavior data recorded",
	})
}

// timeOnSiteHandler handles time-on-site tracking
func timeOnSiteHandler(w http.ResponseWriter, r *http.Request) {
	ip := getIP(r)

	var data struct {
		TimeSpent time.Duration `json:"time_spent"`
	}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid time data", http.StatusBadRequest)
		return
	}

	mu.Lock()
	info, exists := requests[ip]
	if !exists {
		info = &RequestInfo{
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
		requests[ip] = info
	}
	info.TimeOnSite = data.TimeSpent
	mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Time on site recorded",
	})
}

func main() {
	// Start frontend server
	startFrontendServer()

	// Start bot detection API
	http.HandleFunc("/analyze", corsMiddleware(botDetectionHandler))
	http.HandleFunc("/js-challenge", corsMiddleware(jsChallengeHandler))
	http.HandleFunc("/behavior", corsMiddleware(behaviorTrackingHandler))
	http.HandleFunc("/time-on-site", corsMiddleware(timeOnSiteHandler))

	log.Println("✅ Bot Detection API running at http://localhost:8080")
	log.Println("Available endpoints:")
	log.Println("  - /analyze: Main bot detection endpoint")
	log.Println("  - /js-challenge: JavaScript challenge verification")
	log.Println("  - /behavior: User behavior tracking")
	log.Println("  - /time-on-site: Time on site tracking")

	log.Fatal(http.ListenAndServe(":8080", nil))
}
