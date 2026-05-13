package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"wiki-go/internal/config"
)

// --- RequireRole: role hierarchy -------------------------------------------

func TestRequireRole(t *testing.T) {
	cases := []struct {
		name         string
		sessionRole  string
		requiredRole string
		want         bool
	}{
		// admin satisfies everything
		{"admin satisfies admin", "admin", "admin", true},
		{"admin satisfies editor", "admin", "editor", true},
		{"admin satisfies viewer", "admin", "viewer", true},

		// editor satisfies editor and viewer, not admin
		{"editor does not satisfy admin", "editor", "admin", false},
		{"editor satisfies editor", "editor", "editor", true},
		{"editor satisfies viewer", "editor", "viewer", true},

		// viewer satisfies only viewer
		{"viewer does not satisfy admin", "viewer", "admin", false},
		{"viewer does not satisfy editor", "viewer", "editor", false},
		{"viewer satisfies viewer", "viewer", "viewer", true},

		// unknown required role denies
		{"unknown required role denies", "admin", "superadmin", false},
		{"empty required role denies", "admin", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetAuthState(t)
			cfg := newTPAConfig()

			// Build a request with a real session for this role.
			rec := httptest.NewRecorder()
			if err := CreateSession(rec, "u", tc.sessionRole, nil, false, cfg); err != nil {
				t.Fatalf("CreateSession: %v", err)
			}
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			for _, c := range rec.Result().Cookies() {
				req.AddCookie(c)
			}

			if got := RequireRole(req, tc.requiredRole); got != tc.want {
				t.Errorf("RequireRole(%q required, session=%q) = %v, want %v",
					tc.requiredRole, tc.sessionRole, got, tc.want)
			}
		})
	}
}

func TestRequireRole_NilSessionAlwaysDenies(t *testing.T) {
	resetAuthState(t)
	// No cookies on the request — GetSession returns nil.
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	for _, role := range []string{"admin", "editor", "viewer"} {
		if RequireRole(req, role) {
			t.Errorf("nil session must not satisfy role %q", role)
		}
	}
}

// --- GetSession: expiration path -------------------------------------------

func TestGetSession_ExpiredSessionReturnsNilAndIsDeleted(t *testing.T) {
	resetAuthState(t)
	cfg := newTPAConfig()

	// Create a session, then manually expire it in the global map. We can't
	// just sleep — the cookie's MaxAge is 24h. Mutating the map directly is
	// the only way to test the expiration branch without slowing the suite.
	rec := httptest.NewRecorder()
	if err := CreateSession(rec, "expiring-user", "viewer", nil, false, cfg); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	var token *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session_token" {
			token = c
		}
	}
	if token == nil {
		t.Fatal("expected session_token cookie")
	}

	// Force expiration in the in-memory store.
	hashed := hashToken(token.Value)
	mu.Lock()
	s := sessions[hashed]
	s.ExpiresAt = time.Now().Add(-1 * time.Hour)
	sessions[hashed] = s
	mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(token)

	if got := GetSession(req); got != nil {
		t.Errorf("expected nil for expired session, got %+v", got)
	}

	// Expired session must have been removed from the map so a second lookup
	// is fast and consistent. Otherwise the map would grow without bound for
	// every expired-but-not-collected session.
	mu.Lock()
	_, stillPresent := sessions[hashed]
	mu.Unlock()
	if stillPresent {
		t.Error("expired session should be evicted from the map on first lookup")
	}
}

func TestGetSession_NoCookieReturnsNil(t *testing.T) {
	resetAuthState(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := GetSession(req); got != nil {
		t.Errorf("no cookie should return nil, got %+v", got)
	}
}

func TestGetSession_UnknownTokenReturnsNil(t *testing.T) {
	resetAuthState(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_token", Value: "not-a-real-token"})
	if got := GetSession(req); got != nil {
		t.Errorf("unknown token should return nil, got %+v", got)
	}
}

func TestGetSession_UpdatesLastAccessed(t *testing.T) {
	resetAuthState(t)
	cfg := newTPAConfig()

	rec := httptest.NewRecorder()
	if err := CreateSession(rec, "u", "viewer", nil, false, cfg); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	var token *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session_token" {
			token = c
		}
	}
	hashed := hashToken(token.Value)

	// Snapshot LastAccessed, push it back, then verify GetSession advances it.
	mu.Lock()
	s := sessions[hashed]
	s.LastAccessed = time.Now().Add(-30 * time.Minute)
	sessions[hashed] = s
	stale := s.LastAccessed
	mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(token)
	if got := GetSession(req); got == nil {
		t.Fatal("expected session")
	}

	mu.Lock()
	got := sessions[hashed].LastAccessed
	mu.Unlock()
	if !got.After(stale) {
		t.Errorf("LastAccessed should advance after GetSession; was %v, still %v", stale, got)
	}
}

// --- ValidateCredentials: proxy-only users (empty password) ----------------

func TestValidateCredentials_ProxyOnlyUserCannotLoginLocally(t *testing.T) {
	// Users with an empty password are "proxy-only" — they exist so admins can
	// pre-assign roles to SSO-authenticated identities, but the local login
	// form must never accept them. This is a critical privilege boundary.
	cfg := &config.Config{
		Users: []config.User{
			{Username: "sso-only@example.com", Password: "", Role: "admin"},
		},
	}

	ok, role, _ := ValidateCredentials("sso-only@example.com", "", cfg)
	if ok {
		t.Errorf("empty password must not authenticate against empty-password user (role=%q)", role)
	}
	ok, _, _ = ValidateCredentials("sso-only@example.com", "anything", cfg)
	if ok {
		t.Error("any password must not authenticate against empty-password user")
	}
}

func TestValidateCredentials_UnknownUserDenied(t *testing.T) {
	cfg := &config.Config{Users: nil}
	if ok, _, _ := ValidateCredentials("nobody", "pw", cfg); ok {
		t.Error("unknown user must not authenticate")
	}
}
