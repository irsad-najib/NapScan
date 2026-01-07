package middleware

import (
	"log"
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

	// In development, default to NO credentials (so we can safely use "*").
	// Turn on explicitly if you truly need cookies/Authorization with credentials mode.
	allowCredentials := func() bool {
		v := strings.TrimSpace(os.Getenv("CORS_ALLOW_CREDENTIALS"))
		if v == "" {
			return false
		}
		return strings.EqualFold(v, "1") || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
	}

	isProduction := func() bool {
		// Prefer NODE_ENV (as requested). Fall back to ENV for compatibility with existing .env.
		mode := os.Getenv("NODE_ENV")
		if mode == "" {
			mode = os.Getenv("ENV")
		}
		return strings.EqualFold(strings.TrimSpace(mode), "production")
	}

	isDebug := func() bool {
		v := strings.TrimSpace(os.Getenv("CORS_DEBUG"))
		if v == "" {
			return false
		}
		return strings.EqualFold(v, "1") || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
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
		if isDebug() {
			log.Printf("[cors] %s %s origin=%q acr-method=%q acr-headers=%q", c.Request.Method, c.Request.URL.Path, origin, c.Request.Header.Get("Access-Control-Request-Method"), c.Request.Header.Get("Access-Control-Request-Headers"))
		}

		// For development: if no origin header, skip CORS (non-browser client).
		// In production you might want stricter handling.
		if origin == "" {
			c.Next()
			return
		}

		origin = normalizeOrigin(origin)
		if !isAllowedOrigin(origin) {
			if isDebug() {
				log.Printf("[cors] DENIED origin=%q", origin)
			}
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "CORS origin denied"})
			return
		}

		// Set CORS headers IMMEDIATELY so they appear even if handlers error out.
		h := c.Writer.Header()

		creds := allowCredentials()
		// Dev mode target behavior (per request):
		// - credentials=false => Access-Control-Allow-Origin: *
		// - credentials=true  => reflect Origin ("*" is forbidden with credentials)
		if creds {
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Credentials", "true")
			h.Add("Vary", "Origin")
		} else {
			h.Set("Access-Control-Allow-Origin", "*")
			// do NOT send Allow-Credentials when not using credentials
		}

		// These are safe to include on all responses (helps debugging and some clients).
		h.Set("Access-Control-Allow-Methods", strings.Join(allowedMethods, ", "))
		// For actual requests, Allow-Headers isn't required by browsers, but harmless.
		// Use a broad default for dev; preflight will be handled more precisely below.
		h.Set("Access-Control-Allow-Headers", strings.Join(fallbackAllowedHeaders, ", "))

		if len(exposeHeaders) > 0 {
			h.Set("Access-Control-Expose-Headers", strings.Join(exposeHeaders, ", "))
		}

		if isDebug() {
			log.Printf("[cors] ALLOWED origin=%q credentials=%v method=%s path=%s", origin, creds, c.Request.Method, c.Request.URL.Path)
		}

		// Handle preflight OPTIONS
		if c.Request.Method == http.MethodOptions {
			h.Add("Vary", "Access-Control-Request-Method")

			reqHeaders := strings.TrimSpace(c.Request.Header.Get("Access-Control-Request-Headers"))
			if reqHeaders != "" {
				// Mirror requested headers (safer + more flexible than "*")
				h.Set("Access-Control-Allow-Headers", reqHeaders)
				h.Add("Vary", "Access-Control-Request-Headers")
			} else {
				h.Set("Access-Control-Allow-Headers", strings.Join(fallbackAllowedHeaders, ", "))
			}

			h.Set("Access-Control-Allow-Methods", strings.Join(allowedMethods, ", "))
			h.Set("Access-Control-Max-Age", strconv.FormatInt(int64(maxAge.Seconds()), 10))

			if isDebug() {
				log.Printf("[cors] PREFLIGHT OK methods=%q headers=%q maxAge=%ds", h.Get("Access-Control-Allow-Methods"), h.Get("Access-Control-Allow-Headers"), int(maxAge.Seconds()))
			}

			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		// Execute handlers
		c.Next()

		// Debug: log final CORS response headers.
		if isDebug() {
			log.Printf(
				"[cors] RESP status=%d a-c-a-o=%q a-c-a-m=%q a-c-a-h=%q a-c-a-c=%q",
				c.Writer.Status(),
				h.Get("Access-Control-Allow-Origin"),
				h.Get("Access-Control-Allow-Methods"),
				h.Get("Access-Control-Allow-Headers"),
				h.Get("Access-Control-Allow-Credentials"),
			)
		}
	}
}
