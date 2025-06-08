# Advanced Bot Detection System

A comprehensive bot detection system built in Go that uses multiple detection methods to identify and block automated traffic.

## Features

### 1. Header Integrity Checks

- Validates presence of common browser headers
- Checks for suspicious or missing headers
- Analyzes header patterns and combinations

### 2. Behavior Analysis

- Tracks mouse movements
- Monitors scroll events
- Analyzes keyboard activity
- Detects unnatural behavior patterns

### 3. Request Pattern Analysis

- Monitors request frequency
- Analyzes request paths
- Detects suspicious patterns
- Implements rate limiting

### 4. JavaScript Challenge

- Verifies JavaScript execution capability
- Detects headless browsers
- Implements client-side challenges

### 5. Time Analysis

- Tracks time on site
- Monitors request intervals
- Detects rapid, automated requests

### 6. TLS Fingerprinting

- Analyzes TLS client characteristics
- Detects known bot fingerprints
- Identifies suspicious clients

## API Endpoints

### Main Detection Endpoint

```
GET /analyze
```

Analyzes incoming requests for bot detection.

### JavaScript Challenge

```
POST /js-challenge
```

Verifies JavaScript execution capability.

### Behavior Tracking

```
POST /behavior
```

Tracks user behavior metrics.

### Time on Site

```
POST /time-on-site
```

Records time spent on site.

## Configuration

The system is configurable through the `BotDetectionConfig` struct:

```go
type BotDetectionConfig struct {
    MaxRequestsPerMinute int
    MaxRequestsPerHour   int
    SuspiciousUserAgents []string
    WindowSize           time.Duration
    RequiredHeaders      []string
    HoneypotPaths        []string
    CaptchaThreshold     float64
    MinTimeOnSite        time.Duration
    MaxRequestsPerPath   int
    EnableTLSFingerprint bool
    EnableDNSLookup      bool
}
```

## Testing

### Using PowerShell

```powershell
# Test as normal browser
$headers = @{
    "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    "Accept" = "text/html,application/xhtml+xml"
    "Accept-Language" = "en-US,en;q=0.9"
}
Invoke-RestMethod -Uri "http://localhost:8080/analyze" -Headers $headers

# Test as Python requests
$headers = @{
    "User-Agent" = "python-requests/2.28.1"
    "Accept" = "*/*"
}
Invoke-RestMethod -Uri "http://localhost:8080/analyze" -Headers $headers
```

### Using Python

```python
import requests

# Test as normal browser
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'text/html,application/xhtml+xml',
    'Accept-Language': 'en-US,en;q=0.9'
}
response = requests.get('http://localhost:8080/analyze', headers=headers)
print(response.json())

# Test as bot
headers = {
    'User-Agent': 'python-requests/2.28.1',
    'Accept': '*/*'
}
response = requests.get('http://localhost:8080/analyze', headers=headers)
print(response.json())
```

## Frontend Dashboard

The system includes a web-based dashboard that provides:

- Real-time bot detection status
- Behavior tracking visualization
- Request history charts
- Detailed detection metrics
- Interactive testing interface

Access the dashboard at: `http://localhost:3000`

## Detection Methods

### 1. Header Analysis

- Checks for required headers
- Validates header values
- Detects suspicious combinations

### 2. Behavior Tracking

- Mouse movement patterns
- Scroll behavior
- Keyboard activity
- Time between actions

### 3. Request Analysis

- Request frequency
- Path patterns
- Header patterns
- Time patterns

### 4. JavaScript Verification

- Client-side challenges
- Execution timing
- Feature detection

### 5. Time Analysis

- Session duration
- Request intervals
- Action timing

## Response Format

The API returns JSON responses with the following structure:

```json
{
  "ip": "client_ip",
  "request_count": 123,
  "is_bot": true,
  "bot_confidence": 0.85,
  "reasons": [
    "suspicious user agent",
    "high request frequency",
    "missing common headers"
  ],
  "first_seen": "2024-01-01T00:00:00Z",
  "last_seen": "2024-01-01T00:01:00Z",
  "user_agent": "python-requests/2.28.1",
  "unique_paths": 5
}
```

## Running the System

1. Start the backend server:

```bash
go run main.go
```

2. Access the frontend:

```
http://localhost:3000
```

3. Test the API:

```
http://localhost:8080/analyze
```

## Security Considerations

- The system implements multiple layers of detection
- No single method is relied upon exclusively
- Confidence scores are weighted and combined
- Regular updates to detection patterns
- Configurable thresholds and limits

## Contributing

Feel free to submit issues and enhancement requests!

## License

This project is licensed under the MIT License - see the LICENSE file for details.
