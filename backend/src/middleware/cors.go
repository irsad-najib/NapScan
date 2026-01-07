package middleware

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// CORSMiddleware enforces a CORS policy:
// - production: allow only explicit origins
// - non-production: allow any Origin (http/https, any host/IP) for development
//
// Notes:
// - Credentials are enabled, so we never use "*" for Access-Control-Allow-Origin.
// - Preflight (OPTIONS) is handled here and short-circuited.
func CORSMiddleware() gin.HandlerFunc {
	// Keep these lists readable and centralized (no scattered hardcoding).
	allowedMethods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
	fallbackAllowedHeaders := []string{
		"Origin",
		"Content-Type",
		"Authorization",
		"Accept",
		"X-Requested-With",
		"ngrok-skip-browser-warning",
	}
	exposeHeaders := []string{"Content-Length"}
	maxAge := 12 * time.Hour

	// Exact allowlist for production.
	prodAllowedOrigins := map[string]struct{}{
		"http://localhost:3000": {},
	}

	isProduction := func() bool {
		// Prefer NODE_ENV (as requested). Fall back to ENV for compatibility with existing .env.
		mode := os.Getenv("NODE_ENV")
		if mode == "" {
			mode = os.Getenv("ENV")
		}
		return strings.EqualFold(strings.TrimSpace(mode), "production")
	}

	normalizeOrigin := func(origin string) string {
		origin = strings.TrimSpace(origin)
		// Browsers usually send no trailing slash, but normalize just in case.
		origin = strings.TrimRight(origin, "/")
		return origin
	}

	isAllowedOrigin := func(origin string) bool {
		origin = normalizeOrigin(origin)
		if origin == "" {
			return false
		}

		if isProduction() {
			_, ok := prodAllowedOrigins[origin]
			return ok
		}

		// Dev/staging: allow any Origin (including http:// and IP-based origins).
		return true
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin == "" {
			// Non-browser clients typically don't send Origin; skip CORS headers.
			c.Next()
			return
		}

		origin = normalizeOrigin(origin)
		if !isAllowedOrigin(origin) {
			// Explicitly reject disallowed origins (including all http:// in non-production).
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "CORS origin denied"})
			return
		}

		h := c.Writer.Header()
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Allow-Credentials", "true")
		h.Add("Vary", "Origin")

		if len(exposeHeaders) > 0 {
			h.Set("Access-Control-Expose-Headers", strings.Join(exposeHeaders, ", "))
		}

		if c.Request.Method == http.MethodOptions {
			// Handle preflight requests.
			h.Add("Vary", "Access-Control-Request-Method")

			reqHeaders := strings.TrimSpace(c.Request.Header.Get("Access-Control-Request-Headers"))
			if reqHeaders != "" {
				// Safer + flexible: mirror requested headers rather than allowing "*".
				h.Set("Access-Control-Allow-Headers", reqHeaders)
				h.Add("Vary", "Access-Control-Request-Headers")
			} else {
				h.Set("Access-Control-Allow-Headers", strings.Join(fallbackAllowedHeaders, ", "))
			}

			h.Set("Access-Control-Allow-Methods", strings.Join(allowedMethods, ", "))
			h.Set("Access-Control-Max-Age", strconv.FormatInt(int64(maxAge.Seconds()), 10))

			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
