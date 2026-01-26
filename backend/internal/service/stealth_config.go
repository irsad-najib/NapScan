package service

import (
	"math/rand"
	"time"
)

// StealthConfig provides configuration for avoiding fuzzer detection
type StealthConfig struct {
	userAgents []string
	rng        *rand.Rand
}

// NewStealthConfig creates a new stealth configuration
func NewStealthConfig() *StealthConfig {
	return &StealthConfig{
		userAgents: []string{
			// Chrome on Windows 10/11
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
			
			// Firefox on Windows/Linux
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
			"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
			
			// Safari on macOS
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
			
			// Edge on Windows
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
		},
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// GetRandomUserAgent returns a random User-Agent from the pool
func (sc *StealthConfig) GetRandomUserAgent() string {
	return sc.userAgents[sc.rng.Intn(len(sc.userAgents))]
}

// GetBrowserHeaders returns realistic browser headers
func (sc *StealthConfig) GetBrowserHeaders(userAgent string) map[string]string {
	return map[string]string{
		"User-Agent":      userAgent,
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"Accept-Language": "en-US,en;q=0.9",
		"Accept-Encoding": "gzip, deflate, br",
		"DNT":             "1",
		"Connection":      "keep-alive",
		"Upgrade-Insecure-Requests": "1",
		"Sec-Fetch-Dest":  "document",
		"Sec-Fetch-Mode":  "navigate",
		"Sec-Fetch-Site":  "none",
		"Sec-Fetch-User":  "?1",
		"Cache-Control":   "max-age=0",
	}
}

// GetRandomDelay returns a random delay in milliseconds (100-500ms)
func (sc *StealthConfig) GetRandomDelay() int {
	return 100 + sc.rng.Intn(400) // 100-500ms
}

// GetRateLimit returns recommended rate limit (requests per second)
func (sc *StealthConfig) GetRateLimit() int {
	return 10 // 10 requests per second
}

// GetMaxThreads returns recommended max concurrent threads
func (sc *StealthConfig) GetMaxThreads() int {
	return 5 // Limit to 5 concurrent threads
}
