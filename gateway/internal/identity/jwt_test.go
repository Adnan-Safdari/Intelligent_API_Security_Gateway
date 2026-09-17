package identity

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
)

const testSecret = "a-test-secret-of-enough-length"

func segment(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func hs256(t *testing.T, secret string, header, claims any) string {
	t.Helper()
	signed := segment(t, header) + "." + segment(t, claims)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signed))
	return signed + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func hsVerifier(t *testing.T, cfg config.JWTConfig) *Verifier {
	t.Helper()
	cfg.Algorithm = "HS256"
	cfg.SecretEnv = "TEST_JWT_SECRET"
	v, err := NewVerifier(cfg, func(string) string { return testSecret })
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func future() int64 { return time.Now().Add(time.Hour).Unix() }

func TestHS256AcceptsAValidTokenAndReadsTheUser(t *testing.T) {
	v := hsVerifier(t, config.JWTConfig{})
	token := hs256(t, testSecret, map[string]any{"alg": "HS256", "typ": "JWT"}, map[string]any{"sub": 7, "exp": future()})

	caller, err := v.Verify(token)
	if err != nil {
		t.Fatalf("valid token refused: %v", err)
	}
	if caller.ID != "7" || caller.Bypasses {
		t.Errorf("caller = %+v, want id 7 without bypass", caller)
	}
}

func TestForgeriesAreRefused(t *testing.T) {
	v := hsVerifier(t, config.JWTConfig{})
	claims := map[string]any{"sub": "7", "exp": future()}
	valid := hs256(t, testSecret, map[string]any{"alg": "HS256"}, claims)
	parts := strings.Split(valid, ".")

	cases := map[string]string{
		"wrong secret":      hs256(t, "some-other-secret-value", map[string]any{"alg": "HS256"}, claims),
		"alg none":          segment(t, map[string]any{"alg": "none"}) + "." + parts[1] + ".",
		"claims swapped":    parts[0] + "." + segment(t, map[string]any{"sub": "4", "exp": future()}) + "." + parts[2],
		"not a jwt":         "NA==",
		"no exp":            hs256(t, testSecret, map[string]any{"alg": "HS256"}, map[string]any{"sub": "7"}),
		"no user claim":     hs256(t, testSecret, map[string]any{"alg": "HS256"}, map[string]any{"exp": future()}),
		"bad signature b64": parts[0] + "." + parts[1] + ".***",
	}
	for name, token := range cases {
		if _, err := v.Verify(token); !errors.Is(err, ErrForged) {
			t.Errorf("%s: err = %v, want ErrForged", name, err)
		}
	}
}

func TestExpiredTokenIsNotAForgery(t *testing.T) {
	v := hsVerifier(t, config.JWTConfig{})
	token := hs256(t, testSecret, map[string]any{"alg": "HS256"}, map[string]any{"sub": "7", "exp": time.Now().Add(-time.Hour).Unix()})
	if _, err := v.Verify(token); !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
}

func TestIssuerAudienceAndBypass(t *testing.T) {
	v := hsVerifier(t, config.JWTConfig{Issuer: "shop", Audience: "api", BypassClaim: "role", BypassValues: []string{"admin"}})
	header := map[string]any{"alg": "HS256"}

	admin := hs256(t, testSecret, header, map[string]any{"sub": "1", "exp": future(), "iss": "shop", "aud": []string{"api"}, "role": "admin"})
	caller, err := v.Verify(admin)
	if err != nil || !caller.Bypasses {
		t.Errorf("admin: caller=%+v err=%v, want bypass", caller, err)
	}

	user := hs256(t, testSecret, header, map[string]any{"sub": "2", "exp": future(), "iss": "shop", "aud": "api", "role": "user"})
	if caller, err := v.Verify(user); err != nil || caller.Bypasses {
		t.Errorf("user: caller=%+v err=%v, want no bypass", caller, err)
	}

	wrongIssuer := hs256(t, testSecret, header, map[string]any{"sub": "2", "exp": future(), "iss": "elsewhere", "aud": "api"})
	if _, err := v.Verify(wrongIssuer); !errors.Is(err, ErrForged) {
		t.Errorf("wrong issuer: err = %v, want ErrForged", err)
	}
}

func TestFromRequestNeedsABearerToken(t *testing.T) {
	v := hsVerifier(t, config.JWTConfig{})
	r := httptest.NewRequest("GET", "/", nil)
	if _, err := v.FromRequest(r); !errors.Is(err, ErrMissing) {
		t.Errorf("no header: err = %v, want ErrMissing", err)
	}
	r.Header.Set("Authorization", "Basic abc")
	if _, err := v.FromRequest(r); !errors.Is(err, ErrMissing) {
		t.Errorf("basic auth: err = %v, want ErrMissing", err)
	}
}

func TestSecretMustBeAvailableAtBoot(t *testing.T) {
	cfg := config.JWTConfig{Algorithm: "HS256", SecretEnv: "UNSET"}
	if _, err := NewVerifier(cfg, func(string) string { return "" }); err == nil {
		t.Error("a verifier with no secret started")
	}
	cfg.Secret = "fallback-secret-for-demos"
	if _, err := NewVerifier(cfg, func(string) string { return "" }); err != nil {
		t.Errorf("fallback secret refused: %v", err)
	}
	cfg.Secret = "short"
	if _, err := NewVerifier(cfg, func(string) string { return "" }); err == nil {
		t.Error("a short secret was accepted")
	}
}

func TestRS256AndTheKeyConfusionForgery(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "public.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(config.JWTConfig{Algorithm: "RS256", PublicKeyFile: path}, os.Getenv)
	if err != nil {
		t.Fatal(err)
	}

	signed := segment(t, map[string]any{"alg": "RS256"}) + "." + segment(t, map[string]any{"sub": "9", "exp": future()})
	digest := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if caller, err := v.Verify(signed + "." + base64.RawURLEncoding.EncodeToString(signature)); err != nil || caller.ID != "9" {
		t.Errorf("valid RS256: caller=%+v err=%v", caller, err)
	}

	// The classic confusion: sign with HS256 using the public key as the secret.
	confused := hs256(t, string(pemBytes), map[string]any{"alg": "HS256"}, map[string]any{"sub": "9", "exp": future()})
	if _, err := v.Verify(confused); !errors.Is(err, ErrForged) {
		t.Errorf("HS256 signed with the public key: err = %v, want ErrForged", err)
	}
}
