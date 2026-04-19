package api

import "net/http"

// SecurityHeaders is a middleware that sets the phase-9b response
// headers. A baseline set is applied in every mode; HSTS + CSP are
// only safe to send when the panel is actually served over HTTPS
// (panel mode == behind_caddy).
//
// unsafe-inline in script-src / style-src is a known limitation: our
// bundled recharts + tailwind runtime inlines small bits of CSS and
// JS, and moving to nonces is deferred.
func (h *Handlers) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		head := w.Header()
		head.Set("X-Content-Type-Options", "nosniff")
		head.Set("X-Frame-Options", "DENY")
		head.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		head.Set("Permissions-Policy",
			"accelerometer=(), camera=(), geolocation=(), gyroscope=(), "+
				"magnetometer=(), microphone=(), payment=(), usb=()")
		if h.PanelMode == "behind_caddy" {
			head.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			head.Set("Content-Security-Policy",
				"default-src 'self'; "+
					"script-src 'self' 'unsafe-inline'; "+
					"style-src 'self' 'unsafe-inline'; "+
					"img-src 'self' data:; "+
					"connect-src 'self'; "+
					"frame-ancestors 'none'; "+
					"base-uri 'self'; "+
					"form-action 'self'")
		}
		next.ServeHTTP(w, r)
	})
}
