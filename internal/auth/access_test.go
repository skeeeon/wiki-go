package auth

import (
	"testing"

	"wiki-go/internal/config"
)

// --- CanAccessDocument: end-to-end behavior --------------------------------

func TestCanAccessDocument_AdminBypassesEverything(t *testing.T) {
	cfg := &config.Config{}
	cfg.Wiki.Private = true
	cfg.AccessRules = []config.AccessRule{
		{Pattern: "/finance/**", Access: "restricted", Groups: []string{"finance"}},
	}
	admin := &Session{Username: "root", Role: config.RoleAdmin}

	// Admin must reach a restricted path even without the required group.
	if !CanAccessDocument("/finance/q4-report", admin, cfg) {
		t.Error("admin should bypass restricted rule")
	}
	// And any other path.
	if !CanAccessDocument("/anything", admin, cfg) {
		t.Error("admin should bypass private wiki default")
	}
}

func TestCanAccessDocument_NoRule_PublicWiki(t *testing.T) {
	cfg := &config.Config{} // Private=false, no rules

	if !CanAccessDocument("/anything", nil, cfg) {
		t.Error("anonymous should access an unprotected public wiki")
	}
	if !CanAccessDocument("/anything", &Session{Role: "viewer"}, cfg) {
		t.Error("viewer should access an unprotected public wiki")
	}
}

func TestCanAccessDocument_NoRule_PrivateWiki(t *testing.T) {
	cfg := &config.Config{}
	cfg.Wiki.Private = true

	if CanAccessDocument("/anything", nil, cfg) {
		t.Error("anonymous must be denied when wiki is private")
	}
	if !CanAccessDocument("/anything", &Session{Role: "viewer"}, cfg) {
		t.Error("authenticated viewer should access a private wiki without explicit rules")
	}
}

func TestCanAccessDocument_PublicRuleOverridesPrivateWiki(t *testing.T) {
	cfg := &config.Config{}
	cfg.Wiki.Private = true
	cfg.AccessRules = []config.AccessRule{
		{Pattern: "/help/**", Access: "public"},
	}

	if !CanAccessDocument("/help/getting-started", nil, cfg) {
		t.Error("public rule should let anonymous through even when wiki is private")
	}
}

func TestCanAccessDocument_RestrictedRequiresGroupMembership(t *testing.T) {
	cfg := &config.Config{}
	cfg.AccessRules = []config.AccessRule{
		{Pattern: "/finance/**", Access: "restricted", Groups: []string{"finance", "execs"}},
	}

	cases := []struct {
		name    string
		session *Session
		want    bool
	}{
		{"anonymous denied", nil, false},
		{"wrong group denied", &Session{Role: "viewer", Groups: []string{"engineering"}}, false},
		{"no groups denied", &Session{Role: "viewer"}, false},
		{"matching group allowed", &Session{Role: "viewer", Groups: []string{"finance"}}, true},
		{"second-listed group allowed", &Session{Role: "viewer", Groups: []string{"execs"}}, true},
		{"multiple groups including match", &Session{Role: "viewer", Groups: []string{"engineering", "finance"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CanAccessDocument("/finance/q4-report", tc.session, cfg)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCanAccessDocument_PrivateRuleNeedsAuthOnly(t *testing.T) {
	cfg := &config.Config{}
	cfg.AccessRules = []config.AccessRule{
		{Pattern: "/internal/**", Access: "private"},
	}

	if CanAccessDocument("/internal/runbook", nil, cfg) {
		t.Error("private rule must reject anonymous")
	}
	// No group required for private — any authenticated user passes.
	if !CanAccessDocument("/internal/runbook", &Session{Role: "viewer"}, cfg) {
		t.Error("private rule should accept any authenticated user")
	}
}

func TestCanAccessDocument_UnknownAccessLevelDeniesByDefault(t *testing.T) {
	// If a typo lands in config.yaml (`acces: pubic`), the safe behavior is to
	// deny. Verify the default is fail-closed rather than fail-open.
	cfg := &config.Config{}
	cfg.AccessRules = []config.AccessRule{
		{Pattern: "/foo", Access: "pubic"}, // intentional typo
	}

	if CanAccessDocument("/foo", &Session{Role: "admin"}, cfg) {
		// Admin still bypasses via the early-return, so this would unexpectedly pass.
		// Use a non-admin role to actually exercise checkAccessRule's default branch.
	}
	if CanAccessDocument("/foo", &Session{Role: "editor"}, cfg) {
		t.Error("unknown access level must deny authenticated non-admin user")
	}
	if CanAccessDocument("/foo", nil, cfg) {
		t.Error("unknown access level must deny anonymous")
	}
}

func TestCanAccessDocument_FirstMatchingRuleWins(t *testing.T) {
	// Order matters — the first rule whose pattern matches is the one that's
	// applied, even if a later rule would also match. This is load-bearing for
	// the "specific rules above general rules" admin workflow.
	cfg := &config.Config{}
	cfg.AccessRules = []config.AccessRule{
		{Pattern: "/docs/secret/**", Access: "restricted", Groups: []string{"sec"}},
		{Pattern: "/docs/**", Access: "public"},
	}

	if CanAccessDocument("/docs/secret/keys", nil, cfg) {
		t.Error("specific restricted rule should win over later public rule")
	}
	if !CanAccessDocument("/docs/secret/keys", &Session{Role: "viewer", Groups: []string{"sec"}}, cfg) {
		t.Error("user in required group should pass specific rule")
	}
	if !CanAccessDocument("/docs/getting-started", nil, cfg) {
		t.Error("non-matching specific rule should fall through to public")
	}
}

// --- matchPattern: glob translation ---------------------------------------

func TestMatchPattern(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		// Exact matches
		{"exact match", "/foo", "/foo", true},
		{"exact mismatch", "/foo", "/bar", false},
		{"exact does not match prefix", "/foo", "/foo/bar", false},

		// Leading-slash normalization
		{"pattern missing leading slash", "foo", "/foo", true},
		{"path missing leading slash", "/foo", "foo", true},
		{"both missing leading slash", "foo", "foo", true},

		// Single wildcard (does not cross /)
		{"single star matches segment", "/users/*", "/users/alice", true},
		{"single star does not cross slash", "/users/*", "/users/alice/profile", false},
		{"single star at end matches empty", "/users/*", "/users/", true},

		// Double wildcard (crosses /)
		{"double star matches across slashes", "/docs/**", "/docs/a/b/c", true},
		{"double star matches single segment", "/docs/**", "/docs/intro", true},
		{"double star middle of pattern", "/a/**/z", "/a/b/c/z", true},

		// Trailing /** — special "matches parent or any child" form
		{"trailing /** matches parent itself", "/finance/**", "/finance", true},
		{"trailing /** matches trailing slash", "/finance/**", "/finance/", true},
		{"trailing /** matches deep child", "/finance/**", "/finance/2025/q4", true},
		{"trailing /** does not match sibling", "/finance/**", "/financial", false},

		// Question mark — single char, no slash
		{"question mark single char", "/file?.md", "/file1.md", true},
		{"question mark does not cross slash", "/file?", "/file/a", false},

		// /** edge case — only matches root, never deeper paths
		// (this is the rule that prevents a recursive homepage rule from
		// matching the entire wiki — see access.go comment)
		{"slash-doublestar matches root", "/**", "/", true},
		{"slash-doublestar does NOT match deeper paths", "/**", "/anything", false},
		{"slash-doublestar does NOT match nested", "/**", "/a/b", false},

		// Regex-special characters in pattern are quoted
		{"dots are literal", "/docs.html", "/docsxhtml", false},
		{"dots are literal exact", "/docs.html", "/docs.html", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchPattern(tc.pattern, tc.path); got != tc.want {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
			}
		})
	}
}

// --- findMatchingRule -----------------------------------------------------

func TestFindMatchingRule_NilWhenNoMatch(t *testing.T) {
	rules := []config.AccessRule{
		{Pattern: "/foo", Access: "public"},
	}
	if findMatchingRule("/bar", rules) != nil {
		t.Error("expected nil for non-matching path")
	}
}

func TestFindMatchingRule_ReturnsFirstMatch(t *testing.T) {
	rules := []config.AccessRule{
		{Pattern: "/foo/**", Access: "private", Description: "first"},
		{Pattern: "/foo/bar", Access: "public", Description: "second"},
	}
	got := findMatchingRule("/foo/bar", rules)
	if got == nil {
		t.Fatal("expected a match")
	}
	if got.Description != "first" {
		t.Errorf("expected first rule, got %q", got.Description)
	}
}
