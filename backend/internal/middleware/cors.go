package middleware

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// CORSMiddleware enforces a CORS policy using Fiber
func CORSMiddleware() fiber.Handler {
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

	prodAllowedOrigins := map[string]struct{}{
		"http://localhost:3000": {},
	}

	allowCredentials := func() bool {
		v := strings.TrimSpace(os.Getenv("CORS_ALLOW_CREDENTIALS"))
		if v == "" {
			return false
		}
		return strings.EqualFold(v, "1") || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
	}

	isProduction := func() bool {
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
		return true
	}

	return func(c *fiber.Ctx) error {
		origin := c.Get("Origin")
		if isDebug() {
			log.Printf("[cors] %s %s origin=%q acr-method=%q acr-headers=%q", c.Method(), c.Path(), origin, c.Get("Access-Control-Request-Method"), c.Get("Access-Control-Request-Headers"))
		}

		if origin == "" {
			return c.Next()
		}

		origin = normalizeOrigin(origin)
		if !isAllowedOrigin(origin) {
			if isDebug() {
				log.Printf("[cors] DENIED origin=%q", origin)
			}
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "CORS origin denied"})
		}

		creds := allowCredentials()
		if creds {
			c.Set("Access-Control-Allow-Origin", origin)
			c.Set("Access-Control-Allow-Credentials", "true")
			c.Set("Vary", "Origin")
		} else {
			c.Set("Access-Control-Allow-Origin", "*")
		}

		c.Set("Access-Control-Allow-Methods", strings.Join(allowedMethods, ", "))
		c.Set("Access-Control-Allow-Headers", strings.Join(fallbackAllowedHeaders, ", "))

		if len(exposeHeaders) > 0 {
			c.Set("Access-Control-Expose-Headers", strings.Join(exposeHeaders, ", "))
		}

		if isDebug() {
			log.Printf("[cors] ALLOWED origin=%q credentials=%v method=%s path=%s", origin, creds, c.Method(), c.Path())
		}

		if c.Method() == http.MethodOptions {
			c.Set("Vary", "Access-Control-Request-Method")
			reqHeaders := strings.TrimSpace(c.Get("Access-Control-Request-Headers"))
			if reqHeaders != "" {
				c.Set("Access-Control-Allow-Headers", reqHeaders)
				c.Set("Vary", "Access-Control-Request-Headers")
			} else {
				c.Set("Access-Control-Allow-Headers", strings.Join(fallbackAllowedHeaders, ", "))
			}

			c.Set("Access-Control-Allow-Methods", strings.Join(allowedMethods, ", "))
			c.Set("Access-Control-Max-Age", strconv.FormatInt(int64(maxAge.Seconds()), 10))

			if isDebug() {
				log.Printf("[cors] PREFLIGHT OK methods=%q headers=%q maxAge=%ds", c.Get("Access-Control-Allow-Methods"), c.Get("Access-Control-Allow-Headers"), int(maxAge.Seconds()))
			}
			return c.SendStatus(fiber.StatusNoContent)
		}

		err := c.Next()
		
		if isDebug() {
			log.Printf(
				"[cors] RESP status=%d a-c-a-o=%q a-c-a-m=%q a-c-a-h=%q a-c-a-c=%q",
				c.Response().StatusCode(),
				c.GetRespHeader("Access-Control-Allow-Origin"),
				c.GetRespHeader("Access-Control-Allow-Methods"),
				c.GetRespHeader("Access-Control-Allow-Headers"),
				c.GetRespHeader("Access-Control-Allow-Credentials"),
			)
		}
		
		return err
	}
}
