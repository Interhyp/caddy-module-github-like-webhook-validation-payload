package caddy_module_github_webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"io"
	"net/http"
	"strings"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("validate_github_like_webhook_payload", parseCaddyfile)
}

// Middleware implements an HTTP handler.
type Middleware struct {
	Secret     string `json:"secret,omitempty"`
	HeaderName string `json:"headerName,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.github_like_webhook_validation_payload",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Validate implements caddy.Validator.
func (m *Middleware) Validate() error {
	if m.Secret == "" {
		return fmt.Errorf("webhook secret is empty")
	}
	if m.HeaderName == "" {
		return fmt.Errorf("webhook headerName is empty")
	}

	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	var buffer bytes.Buffer
	r.Body = io.NopCloser(io.TeeReader(r.Body, &buffer))
	payloadBytes, err := io.ReadAll(r.Body)
	if err != nil {
		// bad request in case of payload error
		w.WriteHeader(400)
		_, err = w.Write(nil)
		return err
	}
	r.Body = io.NopCloser(&buffer)

	actual := []byte(strings.TrimPrefix(r.Header.Get(m.HeaderName), "sha256="))

	mac := hmac.New(sha256.New, []byte(m.Secret))
	mac.Write(payloadBytes)
	expected := []byte(hex.EncodeToString(mac.Sum(nil)))

	if !hmac.Equal(actual, expected) {
		// unauthorized in case of invalid signature
		w.WriteHeader(401)
		_, err = w.Write(nil)
		return err
	}

	// pass to the next handler
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// consume directive name
	d.Next()

	// require an argument
	if !d.NextArg() {
		return d.ArgErr()
	}

	// store the secret argument
	m.Secret = d.Val()

	// headerName is optional argument
	if d.NextArg() {
		// store the argument
		m.HeaderName = d.Val()
	} else {
		m.HeaderName = "X-Hub-Signature-256"
	}

	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Middleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards
var (
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)
