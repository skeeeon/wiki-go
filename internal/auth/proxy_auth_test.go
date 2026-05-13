package auth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"wiki-go/internal/config"
)

// resetAuthState puts the package's global state into a known-empty form for
// the duration of a single test. Session storage uses t.TempDir(); the config
// file path is pointed at os.DevNull because ensureProxyUserExists persists in
// a fire-and-forget goroutine that would otherwise race with TempDir cleanup.
// The in-memory cfg.Users mutation is synchronous and is what tests verify.
func resetAuthState(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := InitSessionStore(filepath.Join(dir, "sessions.json")); err != nil {
		t.Fatalf("InitSessionStore: %v", err)
	}
	mu.Lock()
	sessions = make(map[string]Session)
	mu.Unlock()
	config.ConfigFilePath = os.DevNull
}

// newTPAConfig returns a config with trusted-proxy-auth enabled and default
// header names/role matching the application defaults.
func newTPAConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Server.AllowInsecureCookies = true // cookies need to work over the test http transport
	cfg.Server.TrustedProxyAuth = config.TrustedProxyAuthConfig{
		Enabled:         true,
		UserHeader:      "X-Forwarded-User",
		EmailHeader:     "X-Forwarded-Email",
		GroupsHeader:    "X-Forwarded-Groups",
		GroupsDelimiter: ",",
		DefaultRole:     "viewer",
		AutoCreateUsers: true,
	}
	return cfg
}

// spyHandler records whether it was invoked and what headers it saw, so tests
// can assert both that the middleware called through and what state the
// downstream handler observes.
type spyHandler struct {
	called bool
	saw    http.Header
}

func (s *spyHandler) ServeHTTP(_ http.ResponseWriter, r *http.Request) {
	s.called = true
	s.saw = r.Header.Clone()
}

// sessionFromResponse looks up the session the middleware created by replaying
// the Set-Cookie header it issued. Returns nil if no session_token cookie was set.
func sessionFromResponse(t *testing.T, rec *httptest.ResponseRecorder) *Session {
	t.Helper()
	var token *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session_token" {
			token = c
			break
		}
	}
	if token == nil {
		return nil
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(token)
	return GetSession(r)
}

// --- middleware behavior -----------------------------------------------------

func TestTrustedProxyAuth_Disabled_IsNoOp(t *testing.T) {
	resetAuthState(t)
	cfg := newTPAConfig()
	cfg.Server.TrustedProxyAuth.Enabled = false

	spy := &spyHandler{}
	h := TrustedProxyAuthMiddleware(cfg, spy)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-User", "alice@example.com")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if !spy.called {
		t.Fatal("next handler was not called")
	}
	if sessionFromResponse(t, rec) != nil {
		t.Fatal("disabled middleware must not create a session")
	}
	// When disabled the middleware is literally a no-op wrapper, so the
	// downstream handler still sees whatever the client sent.
	if got := spy.saw.Get("X-Forwarded-User"); got != "alice@example.com" {
		t.Errorf("downstream header: got %q, want passthrough", got)
	}
}

func TestTrustedProxyAuth_NoHeader_FallsThrough(t *testing.T) {
	resetAuthState(t)
	cfg := newTPAConfig()

	spy := &spyHandler{}
	h := TrustedProxyAuthMiddleware(cfg, spy)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if !spy.called {
		t.Fatal("next handler was not called")
	}
	if sessionFromResponse(t, rec) != nil {
		t.Fatal("no session should be created without an identity header")
	}
}

func TestTrustedProxyAuth_WhitespaceOnlyHeader_FallsThrough(t *testing.T) {
	resetAuthState(t)
	cfg := newTPAConfig()

	spy := &spyHandler{}
	h := TrustedProxyAuthMiddleware(cfg, spy)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-User", "   ")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if sessionFromResponse(t, rec) != nil {
		t.Fatal("whitespace-only user header must not produce a session")
	}
}

func TestTrustedProxyAuth_CreatesSessionFromHeader(t *testing.T) {
	resetAuthState(t)
	cfg := newTPAConfig()

	h := TrustedProxyAuthMiddleware(cfg, &spyHandler{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-User", "alice@example.com")
	req.Header.Set("X-Forwarded-Groups", "engineering,support")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	sess := sessionFromResponse(t, rec)
	if sess == nil {
		t.Fatal("expected session, got nil")
	}
	if sess.Username != "alice@example.com" {
		t.Errorf("username: got %q, want alice@example.com", sess.Username)
	}
	if sess.Role != "viewer" {
		t.Errorf("role: got %q, want viewer (default)", sess.Role)
	}
	if !reflect.DeepEqual(sess.Groups, []string{"engineering", "support"}) {
		t.Errorf("groups: got %v, want [engineering support]", sess.Groups)
	}
}

func TestTrustedProxyAuth_TrimsUsernameWhitespace(t *testing.T) {
	resetAuthState(t)
	cfg := newTPAConfig()

	h := TrustedProxyAuthMiddleware(cfg, &spyHandler{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-User", "  alice@example.com  ")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	sess := sessionFromResponse(t, rec)
	if sess == nil || sess.Username != "alice@example.com" {
		t.Fatalf("expected trimmed username, got %+v", sess)
	}
}

func TestTrustedProxyAuth_ExistingSessionTakesPrecedence(t *testing.T) {
	resetAuthState(t)
	cfg := newTPAConfig()

	// Establish a real session and capture its cookie.
	bootRec := httptest.NewRecorder()
	if err := CreateSession(bootRec, "existing-user", "admin", []string{"sysadmins"}, false, cfg); err != nil {
		t.Fatalf("CreateSession bootstrap: %v", err)
	}
	var token *http.Cookie
	for _, c := range bootRec.Result().Cookies() {
		if c.Name == "session_token" {
			token = c
		}
	}
	if token == nil {
		t.Fatal("expected session_token cookie from bootstrap")
	}

	h := TrustedProxyAuthMiddleware(cfg, &spyHandler{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(token)
	// Attempt to overwrite identity via headers — must be ignored when a
	// session already exists. This is what protects an authenticated user
	// from header-based privilege confusion.
	req.Header.Set("X-Forwarded-User", "attacker@evil.example.com")
	req.Header.Set("X-Forwarded-Groups", "admin,sysadmins")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	for _, c := range rec.Result().Cookies() {
		if c.Name == "session_token" {
			t.Errorf("middleware reissued session_token despite existing session: %q", c.Value)
		}
	}

	// Original session must be untouched.
	probe := httptest.NewRequest(http.MethodGet, "/", nil)
	probe.AddCookie(token)
	sess := GetSession(probe)
	if sess == nil || sess.Username != "existing-user" || sess.Role != "admin" {
		t.Errorf("existing session was clobbered: %+v", sess)
	}
}

// --- CIDR enforcement --------------------------------------------------------

func TestTrustedProxyAuth_UntrustedSource_StripsHeadersAndNoSession(t *testing.T) {
	resetAuthState(t)
	cfg := newTPAConfig()
	cfg.Server.TrustedProxyAuth.TrustedCIDRs = []string{"10.0.0.0/8"}

	spy := &spyHandler{}
	h := TrustedProxyAuthMiddleware(cfg, spy)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-User", "spoofer@example.com")
	req.Header.Set("X-Forwarded-Email", "spoofer@example.com")
	req.Header.Set("X-Forwarded-Groups", "admins")
	req.RemoteAddr = "203.0.113.5:54321" // outside 10.0.0.0/8
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if sessionFromResponse(t, rec) != nil {
		t.Fatal("untrusted source must not produce a session")
	}
	for _, name := range []string{"X-Forwarded-User", "X-Forwarded-Email", "X-Forwarded-Groups"} {
		if v := spy.saw.Get(name); v != "" {
			t.Errorf("header %s should be stripped before downstream sees it, got %q", name, v)
		}
	}
}

func TestTrustedProxyAuth_TrustedSource_CreatesSession(t *testing.T) {
	resetAuthState(t)
	cfg := newTPAConfig()
	cfg.Server.TrustedProxyAuth.TrustedCIDRs = []string{"10.0.0.0/8"}

	h := TrustedProxyAuthMiddleware(cfg, &spyHandler{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-User", "bob@example.com")
	req.RemoteAddr = "10.1.2.3:54321"
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	sess := sessionFromResponse(t, rec)
	if sess == nil || sess.Username != "bob@example.com" {
		t.Fatalf("expected session for bob from trusted source, got %+v", sess)
	}
}

// --- auto-create-users -------------------------------------------------------

func TestTrustedProxyAuth_AutoCreateUsersAddsToConfig(t *testing.T) {
	resetAuthState(t)
	cfg := newTPAConfig()
	cfg.Server.TrustedProxyAuth.AutoCreateUsers = true

	h := TrustedProxyAuthMiddleware(cfg, &spyHandler{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-User", "new-user@example.com")
	req.Header.Set("X-Forwarded-Groups", "support")

	h.ServeHTTP(httptest.NewRecorder(), req)

	var found *config.User
	for i := range cfg.Users {
		if cfg.Users[i].Username == "new-user@example.com" {
			found = &cfg.Users[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected new-user@example.com to be added; cfg.Users = %+v", cfg.Users)
	}
	if found.Role != "viewer" {
		t.Errorf("role: got %q, want viewer (default)", found.Role)
	}
	if found.Password != "" {
		t.Errorf("auto-created user must have empty password (proxy-only), got %q", found.Password)
	}
	if !reflect.DeepEqual(found.Groups, []string{"support"}) {
		t.Errorf("groups: got %v, want [support]", found.Groups)
	}
}

func TestTrustedProxyAuth_AutoCreateUsersDisabledKeepsConfigClean(t *testing.T) {
	resetAuthState(t)
	cfg := newTPAConfig()
	cfg.Server.TrustedProxyAuth.AutoCreateUsers = false

	h := TrustedProxyAuthMiddleware(cfg, &spyHandler{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-User", "transient@example.com")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	for _, u := range cfg.Users {
		if u.Username == "transient@example.com" {
			t.Fatalf("user should not be appended when AutoCreateUsers=false; cfg.Users = %+v", cfg.Users)
		}
	}
	// A session still gets created — the user just isn't persisted to the config.
	if sessionFromResponse(t, rec) == nil {
		t.Fatal("session should still be created when AutoCreateUsers=false")
	}
}

func TestTrustedProxyAuth_DoesNotDuplicateExistingUser(t *testing.T) {
	resetAuthState(t)
	cfg := newTPAConfig()
	cfg.Users = []config.User{{
		Username: "alice@example.com",
		Role:     "admin",
		Groups:   []string{"sysadmins"},
	}}

	h := TrustedProxyAuthMiddleware(cfg, &spyHandler{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-User", "alice@example.com")
	req.Header.Set("X-Forwarded-Groups", "support") // additional group from the proxy
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	count := 0
	for _, u := range cfg.Users {
		if u.Username == "alice@example.com" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 alice entry, got %d (cfg.Users=%+v)", count, cfg.Users)
	}

	sess := sessionFromResponse(t, rec)
	if sess == nil {
		t.Fatal("expected session, got nil")
	}
	if sess.Role != "admin" {
		t.Errorf("session role: got %q, want admin (config wins over default)", sess.Role)
	}
	if !reflect.DeepEqual(sess.Groups, []string{"sysadmins", "support"}) {
		t.Errorf("session groups: got %v, want [sysadmins support] (config + header merged)", sess.Groups)
	}
}

// --- pure helpers (no global state required) ---------------------------------

func TestResolveProxyRoleAndGroups(t *testing.T) {
	cases := []struct {
		name        string
		configUsers []config.User
		username    string
		groupsHdr   string
		delimiter   string
		defaultRole string
		wantRole    string
		wantGroups  []string
	}{
		{
			name:        "new user gets default role",
			username:    "new@example.com",
			groupsHdr:   "g1,g2",
			delimiter:   ",",
			defaultRole: "viewer",
			wantRole:    "viewer",
			wantGroups:  []string{"g1", "g2"},
		},
		{
			name: "known user keeps config role and merges groups",
			configUsers: []config.User{
				{Username: "alice", Role: "admin", Groups: []string{"sys"}},
			},
			username:    "alice",
			groupsHdr:   "extra",
			delimiter:   ",",
			defaultRole: "viewer",
			wantRole:    "admin",
			wantGroups:  []string{"sys", "extra"},
		},
		{
			name: "known user with empty role falls back to default",
			configUsers: []config.User{
				{Username: "bob", Role: "", Groups: nil},
			},
			username:    "bob",
			delimiter:   ",",
			defaultRole: "editor",
			wantRole:    "editor",
			wantGroups:  nil,
		},
		{
			name:        "custom delimiter splits correctly",
			username:    "carol",
			groupsHdr:   "g1|g2|g3",
			delimiter:   "|",
			defaultRole: "viewer",
			wantRole:    "viewer",
			wantGroups:  []string{"g1", "g2", "g3"},
		},
		{
			name:        "empty delimiter defaults to comma",
			username:    "dave",
			groupsHdr:   "a,b",
			delimiter:   "",
			defaultRole: "viewer",
			wantRole:    "viewer",
			wantGroups:  []string{"a", "b"},
		},
		{
			name:        "trims whitespace and drops empty groups",
			username:    "erin",
			groupsHdr:   " a , , b ,  ",
			delimiter:   ",",
			defaultRole: "viewer",
			wantRole:    "viewer",
			wantGroups:  []string{"a", "b"},
		},
		{
			name: "merged groups are deduplicated, config order preserved",
			configUsers: []config.User{
				{Username: "frank", Role: "editor", Groups: []string{"a", "b"}},
			},
			username:    "frank",
			groupsHdr:   "b,c,a",
			delimiter:   ",",
			defaultRole: "viewer",
			wantRole:    "editor",
			wantGroups:  []string{"a", "b", "c"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Users: tc.configUsers}
			cfg.Server.TrustedProxyAuth = config.TrustedProxyAuthConfig{
				GroupsHeader:    "X-Forwarded-Groups",
				GroupsDelimiter: tc.delimiter,
				DefaultRole:     tc.defaultRole,
			}
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.groupsHdr != "" {
				r.Header.Set("X-Forwarded-Groups", tc.groupsHdr)
			}
			role, groups := resolveProxyRoleAndGroups(tc.username, r, cfg)
			if role != tc.wantRole {
				t.Errorf("role: got %q, want %q", role, tc.wantRole)
			}
			if !reflect.DeepEqual(groups, tc.wantGroups) {
				t.Errorf("groups: got %v, want %v", groups, tc.wantGroups)
			}
		})
	}
}

func TestIsFromTrustedSource(t *testing.T) {
	nets := parseCIDRs([]string{"10.0.0.0/8", "::1/128"})

	cases := []struct {
		name   string
		remote string
		want   bool
	}{
		{"trusted IPv4 with port", "10.1.2.3:54321", true},
		{"trusted IPv4 without port", "10.1.2.3", true},
		{"untrusted IPv4", "203.0.113.5:54321", false},
		{"trusted IPv6 with port", "[::1]:54321", true},
		{"malformed remote", "not-an-ip:abc", false},
		{"empty remote", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remote
			if got := isFromTrustedSource(r, nets); got != tc.want {
				t.Errorf("got %v, want %v for remote=%q", got, tc.want, tc.remote)
			}
		})
	}
}

func TestParseCIDRs_InvalidEntriesAreSkipped(t *testing.T) {
	nets := parseCIDRs([]string{
		"10.0.0.0/8",
		"not-a-cidr",
		"",
		"  ",
		"192.168.1.0/24",
	})
	if len(nets) != 2 {
		t.Fatalf("expected 2 valid CIDRs, got %d (%v)", len(nets), nets)
	}
}

func TestMergeUniqueStrings(t *testing.T) {
	cases := []struct {
		name       string
		a, b, want []string
	}{
		{"both nil returns nil", nil, nil, nil},
		{"no overlap concatenates", []string{"a", "b"}, []string{"c"}, []string{"a", "b", "c"}},
		{"full overlap dedups", []string{"a", "b"}, []string{"b", "a"}, []string{"a", "b"}},
		{"preserves first-seen order", []string{"z", "a"}, []string{"a", "b"}, []string{"z", "a", "b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeUniqueStrings(tc.a, tc.b)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
