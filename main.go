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
}

// BotDetectionConfig holds configuration for bot detection
type BotDetectionConfig struct {
	MaxRequestsPerMinute int
	MaxRequestsPerHour   int
	SuspiciousUserAgents []string
	WindowSize           time.Duration
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

	// Check request frequency
	if info.Count > config.MaxRequestsPerMinute {
		info.Reasons = append(info.Reasons, "high request frequency")
		info.BotConfidence += 0.4
	}

	// Check user agent
	userAgent := strings.ToLower(r.UserAgent())
	for _, suspicious := range config.SuspiciousUserAgents {
		if strings.Contains(userAgent, suspicious) {
			info.Reasons = append(info.Reasons, "suspicious user agent")
			info.BotConfidence += 0.3
			break
		}
	}

	// Check request pattern
	if len(info.RequestPaths) > 1 {
		// Check for rapid repeated requests to the same endpoint
		lastPath := info.RequestPaths[len(info.RequestPaths)-2]
		currentPath := info.RequestPaths[len(info.RequestPaths)-1]
		if lastPath == currentPath &&
			info.RequestTimes[len(info.RequestTimes)-1].Sub(info.RequestTimes[len(info.RequestTimes)-2]) < time.Second {
			info.Reasons = append(info.Reasons, "repetitive request pattern")
			info.BotConfidence += 0.3
		}
	}

	// Determine if it's a bot based on confidence
	info.IsBot = info.BotConfidence >= 0.5
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

func main() {
	// Start frontend server
	startFrontendServer()

	// Start bot detection API
	http.HandleFunc("/analyze", corsMiddleware(botDetectionHandler))
	log.Println("✅ Bot Detection API running at http://localhost:8080/analyze")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
