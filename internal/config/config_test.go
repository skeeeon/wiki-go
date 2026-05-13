package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// --- LoadConfig: first-run / defaults --------------------------------------

func TestLoadConfig_MissingFileCreatesDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "config.yaml") // parent dir doesn't exist either

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	// File must now exist.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected config file to be created at %s, got %v", path, err)
	}

	// Critical default: a default admin user must be created so the operator
	// can actually log in on first run. Losing this would brick fresh installs.
	if len(cfg.Users) != 1 || cfg.Users[0].Username != "admin" || cfg.Users[0].Role != RoleAdmin {
		t.Errorf("expected single admin user on first run, got %+v", cfg.Users)
	}
	if cfg.Users[0].Password == "" {
		t.Error("default admin must have a hashed password (not empty)")
	}

	// A few other defaults that are load-bearing for safety.
	if cfg.Server.AllowInsecureCookies {
		t.Error("AllowInsecureCookies must default to false (Secure cookies on)")
	}
	if cfg.Server.TrustedProxyAuth.Enabled {
		t.Error("TrustedProxyAuth.Enabled must default to false")
	}
	if cfg.Security.PasswordStrength < 10 {
		t.Errorf("PasswordStrength default too low: %d", cfg.Security.PasswordStrength)
	}
}

// --- SaveConfig → LoadConfig roundtrip -------------------------------------
//
// SaveConfig formats via a printf template (one field per %s/%t/%d), so a typo
// in the template silently drops data on disk. These tests catch that class
// of bug for every field group that has tripped users in the past.

func TestRoundTrip_AccessRulesPreserved(t *testing.T) {
	// Most important roundtrip: access rules drive the "customer vs internal"
	// split. A silent drop here would make internal content publicly readable.
	original := minimalConfig()
	original.AccessRules = []AccessRule{
		{Pattern: "/internal/**", Access: "restricted", Groups: []string{"staff", "leads"}, Description: "internal runbooks"},
		{Pattern: "/help/**", Access: "public"},
	}

	got := roundtrip(t, original)

	if len(got.AccessRules) != 2 {
		t.Fatalf("expected 2 rules, got %d (%+v)", len(got.AccessRules), got.AccessRules)
	}
	r0 := got.AccessRules[0]
	if r0.Pattern != "/internal/**" || r0.Access != "restricted" {
		t.Errorf("rule 0 pattern/access not preserved: %+v", r0)
	}
	if len(r0.Groups) != 2 || r0.Groups[0] != "staff" || r0.Groups[1] != "leads" {
		t.Errorf("rule 0 groups not preserved: %+v", r0.Groups)
	}
	if r0.Description != "internal runbooks" {
		t.Errorf("rule 0 description not preserved: %q", r0.Description)
	}
	if got.AccessRules[1].Pattern != "/help/**" || got.AccessRules[1].Access != "public" {
		t.Errorf("rule 1 not preserved: %+v", got.AccessRules[1])
	}
}

func TestRoundTrip_UserGroupsPreserved(t *testing.T) {
	original := minimalConfig()
	original.Users = []User{
		{Username: "alice", Password: "$2a$10$abc", Role: "admin", Groups: []string{"staff"}},
		{Username: "bob", Password: "", Role: "viewer", Groups: []string{"customers", "beta-testers"}},
	}

	got := roundtrip(t, original)

	if len(got.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(got.Users))
	}
	if got.Users[0].Username != "alice" || got.Users[0].Role != "admin" {
		t.Errorf("user 0 not preserved: %+v", got.Users[0])
	}
	if len(got.Users[0].Groups) != 1 || got.Users[0].Groups[0] != "staff" {
		t.Errorf("user 0 groups not preserved: %+v", got.Users[0].Groups)
	}
	// bob has Password="" — must be preserved as a proxy-only user, not dropped.
	if got.Users[1].Password != "" {
		t.Errorf("proxy-only user's empty password should roundtrip, got %q", got.Users[1].Password)
	}
	if len(got.Users[1].Groups) != 2 {
		t.Errorf("user 1 groups: got %+v, want 2 entries", got.Users[1].Groups)
	}
}

func TestRoundTrip_TrustedProxyAuthPreserved(t *testing.T) {
	// The whole reason this deployment shape exists — these fields must
	// survive roundtrips intact, including the CIDR list which has a custom
	// formatter that's easy to break.
	original := minimalConfig()
	original.Server.TrustedProxyAuth = TrustedProxyAuthConfig{
		Enabled:         true,
		UserHeader:      "X-Forwarded-User",
		EmailHeader:     "X-Forwarded-Email",
		GroupsHeader:    "X-Forwarded-Groups",
		GroupsDelimiter: "|",
		DefaultRole:     "viewer",
		AutoCreateUsers: true,
		LogoutURL:       "/oauth2/sign_out",
		TrustedCIDRs:    []string{"10.0.0.0/8", "192.168.0.0/16"},
	}

	got := roundtrip(t, original)

	tpa := got.Server.TrustedProxyAuth
	if !tpa.Enabled {
		t.Error("Enabled not preserved")
	}
	if tpa.UserHeader != "X-Forwarded-User" {
		t.Errorf("UserHeader: %q", tpa.UserHeader)
	}
	if tpa.GroupsDelimiter != "|" {
		t.Errorf("GroupsDelimiter (custom): got %q, want '|'", tpa.GroupsDelimiter)
	}
	if tpa.LogoutURL != "/oauth2/sign_out" {
		t.Errorf("LogoutURL: %q", tpa.LogoutURL)
	}
	if len(tpa.TrustedCIDRs) != 2 || tpa.TrustedCIDRs[0] != "10.0.0.0/8" || tpa.TrustedCIDRs[1] != "192.168.0.0/16" {
		t.Errorf("TrustedCIDRs not preserved: %+v", tpa.TrustedCIDRs)
	}
}

func TestRoundTrip_EmptyTrustedCIDRsStaysEmpty(t *testing.T) {
	// formatTrustedCIDRs has two branches (empty list emits `[]`, non-empty
	// emits a YAML sequence). Verify the empty path doesn't get parsed back
	// as a list with one empty element.
	original := minimalConfig()
	original.Server.TrustedProxyAuth.TrustedCIDRs = nil

	got := roundtrip(t, original)
	if len(got.Server.TrustedProxyAuth.TrustedCIDRs) != 0 {
		t.Errorf("empty CIDR list should roundtrip as empty, got %+v",
			got.Server.TrustedProxyAuth.TrustedCIDRs)
	}
}

func TestRoundTrip_SecurityLoginBanPreserved(t *testing.T) {
	original := minimalConfig()
	original.Security.PasswordStrength = 12
	original.Security.LoginBan.Enabled = true
	original.Security.LoginBan.MaxFailures = 3
	original.Security.LoginBan.WindowSeconds = 60
	original.Security.LoginBan.InitialBanSeconds = 30
	original.Security.LoginBan.MaxBanSeconds = 7200

	got := roundtrip(t, original)

	if got.Security.PasswordStrength != 12 {
		t.Errorf("PasswordStrength: got %d", got.Security.PasswordStrength)
	}
	if got.Security.LoginBan.MaxFailures != 3 {
		t.Errorf("MaxFailures: got %d", got.Security.LoginBan.MaxFailures)
	}
	if got.Security.LoginBan.MaxBanSeconds != 7200 {
		t.Errorf("MaxBanSeconds: got %d", got.Security.LoginBan.MaxBanSeconds)
	}
}

func TestRoundTrip_WikiBooleansPreserved(t *testing.T) {
	// Every wiki-level boolean flag has its own template substitution. A
	// regression that prints %!t(MISSING) for one of them would silently
	// reset it to false on save.
	original := minimalConfig()
	original.Wiki.Private = true
	original.Wiki.DisableComments = true
	original.Wiki.DisableFileUploadChecking = true
	original.Wiki.EnableLinkEmbedding = true
	original.Wiki.HideAttachments = true
	original.Wiki.DisableContentMaxWidth = true
	original.Wiki.AlwaysOpenChildrenInSidebar = true

	got := roundtrip(t, original)

	checks := []struct {
		name string
		got  bool
	}{
		{"Private", got.Wiki.Private},
		{"DisableComments", got.Wiki.DisableComments},
		{"DisableFileUploadChecking", got.Wiki.DisableFileUploadChecking},
		{"EnableLinkEmbedding", got.Wiki.EnableLinkEmbedding},
		{"HideAttachments", got.Wiki.HideAttachments},
		{"DisableContentMaxWidth", got.Wiki.DisableContentMaxWidth},
		{"AlwaysOpenChildrenInSidebar", got.Wiki.AlwaysOpenChildrenInSidebar},
	}
	for _, c := range checks {
		if !c.got {
			t.Errorf("Wiki.%s did not roundtrip as true", c.name)
		}
	}
}

// --- SaveConfig: rendered output is valid YAML ----------------------------

func TestSaveConfig_OutputIsValidYAML(t *testing.T) {
	cfg := minimalConfig()
	cfg.AccessRules = []AccessRule{
		{Pattern: "/x", Access: "restricted", Groups: []string{"a", "b"}, Description: "test"},
	}
	cfg.Users = []User{
		{Username: "u", Password: "h", Role: "admin", Groups: []string{"g1"}},
	}

	var buf bytes.Buffer
	if err := SaveConfig(cfg, &buf); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	// Re-parse the output as generic YAML. If the template ever emits
	// invalid YAML (extra %!s, bad indentation, missing colon) this fails.
	var parsed map[string]any
	if err := yaml.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("SaveConfig output is not valid YAML: %v\n---\n%s", err, buf.String())
	}
	// And it must not contain Go's format-error sentinels — that's the
	// specific bug FixBrokenConfig was created to clean up after.
	if bytes.Contains(buf.Bytes(), []byte("%!")) {
		t.Errorf("SaveConfig output contains format-error sentinel:\n%s", buf.String())
	}
}

// --- helpers ---------------------------------------------------------------

// minimalConfig returns a Config with every required field populated, so the
// template formatter can render without panicking on zero values.
func minimalConfig() *Config {
	cfg := &Config{}
	cfg.Server.Host = "0.0.0.0"
	cfg.Server.Port = 8080
	cfg.Server.TrustedProxyAuth = TrustedProxyAuthConfig{
		UserHeader:      "X-Forwarded-User",
		EmailHeader:     "X-Forwarded-Email",
		GroupsHeader:    "X-Forwarded-Groups",
		GroupsDelimiter: ",",
		DefaultRole:     "viewer",
	}
	cfg.Wiki.RootDir = "data"
	cfg.Wiki.DocumentsDir = "documents"
	cfg.Wiki.Title = "Wiki"
	cfg.Wiki.Owner = "owner"
	cfg.Wiki.Notice = "notice"
	cfg.Wiki.Timezone = "UTC"
	cfg.Wiki.Language = "en"
	cfg.Wiki.MaxVersions = 10
	cfg.Wiki.MaxUploadSize = 10
	cfg.Security.PasswordStrength = 10
	return cfg
}

// roundtrip writes cfg via SaveConfig, reads it back via yaml.Unmarshal, and
// returns the result. Using Unmarshal directly (rather than LoadConfig) avoids
// ensureCompleteConfig rewriting the file in the middle of the test.
func roundtrip(t *testing.T, cfg *Config) *Config {
	t.Helper()
	var buf bytes.Buffer
	if err := SaveConfig(cfg, &buf); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	out := &Config{}
	if err := yaml.Unmarshal(buf.Bytes(), out); err != nil {
		t.Fatalf("Unmarshal: %v\n---\n%s", err, buf.String())
	}
	return out
}
