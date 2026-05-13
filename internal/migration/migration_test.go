package migration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// --- FixBrokenConfig -------------------------------------------------------

func TestFixBrokenConfig_MissingFileIsNotAnError(t *testing.T) {
	// Startup runs this before LoadConfig creates the default file, so a
	// missing config must succeed silently.
	path := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	if err := FixBrokenConfig(path); err != nil {
		t.Errorf("expected nil error for missing file, got %v", err)
	}
}

func TestFixBrokenConfig_CleanFileIsLeftAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	original := "server:\n  host: 0.0.0.0\nusers:\n  - username: admin\n    role: admin\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := FixBrokenConfig(path); err != nil {
		t.Fatalf("FixBrokenConfig: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Errorf("clean file should be untouched\nwant: %q\n got: %q", original, string(got))
	}
}

func TestFixBrokenConfig_RemovesCorruptionMarker(t *testing.T) {
	// The corruption is the literal Go format-string sentinel "%!s(MISSING)"
	// that an older config template emitted when an argument was absent.
	// FixBrokenConfig must strip it and leave the rest of the file valid YAML.
	path := filepath.Join(t.TempDir(), "config.yaml")
	broken := "server:\n  host: 0.0.0.0\naccess_rules:\n%!s(MISSING)users:\n  - username: admin\n"
	if err := os.WriteFile(path, []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := FixBrokenConfig(path); err != nil {
		t.Fatalf("FixBrokenConfig: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "%!s(MISSING)") {
		t.Errorf("corruption marker should be stripped, got %q", string(got))
	}

	// And the result must still parse as YAML.
	var parsed map[string]any
	if err := yaml.Unmarshal(got, &parsed); err != nil {
		t.Errorf("fixed config must still be valid YAML: %v\ncontent: %q", err, string(got))
	}
}

// --- MigrateUserRoles ------------------------------------------------------

func TestMigrateUserRoles_MissingFileIsNotAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	if err := MigrateUserRoles(path); err != nil {
		t.Errorf("expected nil error for missing file, got %v", err)
	}
}

func TestMigrateUserRoles_IsAdminTrueBecomesAdminRole(t *testing.T) {
	path := writeTempConfig(t, `
users:
  - username: alice
    password: hash
    is_admin: true
`)

	if err := MigrateUserRoles(path); err != nil {
		t.Fatalf("MigrateUserRoles: %v", err)
	}

	cfg := readConfig(t, path)
	if len(cfg.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(cfg.Users))
	}
	u := cfg.Users[0]
	if u.Role != "admin" {
		t.Errorf("role: got %q, want admin", u.Role)
	}
	if u.IsAdmin {
		// The IsAdmin field must be cleared so the next migration run is a
		// no-op rather than re-running.
		t.Error("IsAdmin field should be cleared after migration")
	}
}

func TestMigrateUserRoles_IsAdminFalseBecomesViewerRole(t *testing.T) {
	path := writeTempConfig(t, `
users:
  - username: bob
    password: hash
    is_admin: false
`)

	if err := MigrateUserRoles(path); err != nil {
		t.Fatalf("MigrateUserRoles: %v", err)
	}

	cfg := readConfig(t, path)
	if cfg.Users[0].Role != "viewer" {
		t.Errorf("role: got %q, want viewer", cfg.Users[0].Role)
	}
}

func TestMigrateUserRoles_EmptyRoleDefaultsToViewer(t *testing.T) {
	// A user with neither IsAdmin nor Role set (e.g., a partially-broken
	// config) must end up as a viewer rather than being silently dropped.
	path := writeTempConfig(t, `
users:
  - username: orphan
    password: hash
`)

	if err := MigrateUserRoles(path); err != nil {
		t.Fatalf("MigrateUserRoles: %v", err)
	}

	cfg := readConfig(t, path)
	if cfg.Users[0].Role != "viewer" {
		t.Errorf("role: got %q, want viewer", cfg.Users[0].Role)
	}
}

func TestMigrateUserRoles_AlreadyMigratedFileIsUntouched(t *testing.T) {
	// If every user already has a role and no IsAdmin field, the function
	// must NOT rewrite the file — that would create gratuitous .bak backups
	// on every restart.
	path := writeTempConfig(t, `
users:
  - username: alice
    password: hash
    role: admin
  - username: bob
    password: hash
    role: editor
`)

	beforeStat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := MigrateUserRoles(path); err != nil {
		t.Fatalf("MigrateUserRoles: %v", err)
	}

	afterStat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !beforeStat.ModTime().Equal(afterStat.ModTime()) {
		t.Errorf("file should not have been rewritten when no migration is needed")
	}

	// No backup file should exist either.
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".bak") {
			t.Errorf("unexpected backup file created: %s", e.Name())
		}
	}
}

func TestMigrateUserRoles_CreatesBackupBeforeRewriting(t *testing.T) {
	// When migration runs, the original file is preserved as a timestamped
	// .bak before being overwritten. This is the safety net.
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	original := "users:\n  - username: alice\n    is_admin: true\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := MigrateUserRoles(path); err != nil {
		t.Fatalf("MigrateUserRoles: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	backupFound := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "config.yaml.") && strings.HasSuffix(e.Name(), ".bak") {
			backupFound = true
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != original {
				t.Errorf("backup contents differ from original\nwant: %q\n got: %q", original, string(data))
			}
		}
	}
	if !backupFound {
		t.Errorf("expected a .bak file in %s, found: %v", dir, entries)
	}
}

func TestMigrateUserRoles_PreservesUnrelatedFields(t *testing.T) {
	// Regression test for the silent-data-loss bug fixed by mirroring
	// config.Config's full field set in migration.Config. If migration ever
	// drops sections like access_rules, security, or trusted_proxy_auth
	// during the YAML roundtrip, this test fails.
	path := writeTempConfig(t, `
server:
  host: 0.0.0.0
  trusted_proxy_auth:
    enabled: true
    user_header: X-Forwarded-User
    trusted_cidrs:
      - "10.0.0.0/8"
wiki:
  enable_link_embedding: true
  hide_attachments: true
security:
  passwordstrength: 12
  login_ban:
    enabled: true
    max_failures: 3
access_rules:
  - pattern: /internal/**
    access: restricted
    groups: [staff]
    description: internal only
users:
  - username: alice
    password: hash
    is_admin: true
`)

	if err := MigrateUserRoles(path); err != nil {
		t.Fatalf("MigrateUserRoles: %v", err)
	}

	cfg := readConfig(t, path)

	// Migration did its job.
	if cfg.Users[0].Role != "admin" {
		t.Errorf("alice role: got %q, want admin", cfg.Users[0].Role)
	}

	// And every other section survived.
	if !cfg.Server.TrustedProxyAuth.Enabled {
		t.Error("trusted_proxy_auth.enabled was dropped during migration")
	}
	if cfg.Server.TrustedProxyAuth.UserHeader != "X-Forwarded-User" {
		t.Errorf("trusted_proxy_auth.user_header dropped: %q", cfg.Server.TrustedProxyAuth.UserHeader)
	}
	if len(cfg.Server.TrustedProxyAuth.TrustedCIDRs) != 1 {
		t.Errorf("trusted_cidrs dropped: %+v", cfg.Server.TrustedProxyAuth.TrustedCIDRs)
	}
	if !cfg.Wiki.EnableLinkEmbedding {
		t.Error("wiki.enable_link_embedding dropped")
	}
	if !cfg.Wiki.HideAttachments {
		t.Error("wiki.hide_attachments dropped")
	}
	if cfg.Security.PasswordStrength != 12 {
		t.Errorf("security.passwordstrength dropped: got %d", cfg.Security.PasswordStrength)
	}
	if cfg.Security.LoginBan.MaxFailures != 3 {
		t.Errorf("security.login_ban.max_failures dropped: got %d", cfg.Security.LoginBan.MaxFailures)
	}
	if len(cfg.AccessRules) != 1 {
		t.Fatalf("access_rules dropped: got %d, want 1", len(cfg.AccessRules))
	}
	if cfg.AccessRules[0].Pattern != "/internal/**" || cfg.AccessRules[0].Description != "internal only" {
		t.Errorf("access_rules content not preserved: %+v", cfg.AccessRules[0])
	}
}

func TestMigrateUserRoles_PreservesUserGroups(t *testing.T) {
	// Same regression: user groups must survive migration, since migration.User
	// previously didn't have a Groups field.
	path := writeTempConfig(t, `
users:
  - username: alice
    password: hash
    is_admin: true
    groups:
      - staff
      - leads
`)

	if err := MigrateUserRoles(path); err != nil {
		t.Fatalf("MigrateUserRoles: %v", err)
	}

	cfg := readConfig(t, path)
	if cfg.Users[0].Role != "admin" {
		t.Errorf("role not migrated: %q", cfg.Users[0].Role)
	}
	if len(cfg.Users[0].Groups) != 2 || cfg.Users[0].Groups[0] != "staff" || cfg.Users[0].Groups[1] != "leads" {
		t.Errorf("user groups dropped during migration: %+v", cfg.Users[0].Groups)
	}
}

func TestMigrateUserRoles_PreservesExistingRolesWhenMixed(t *testing.T) {
	// A common case: one user has IsAdmin=true (needs migration), another
	// has a real role already (should be preserved untouched).
	path := writeTempConfig(t, `
users:
  - username: alice
    password: hash
    is_admin: true
  - username: bob
    password: hash
    role: editor
`)

	if err := MigrateUserRoles(path); err != nil {
		t.Fatalf("MigrateUserRoles: %v", err)
	}

	cfg := readConfig(t, path)
	if len(cfg.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(cfg.Users))
	}
	roles := map[string]string{}
	for _, u := range cfg.Users {
		roles[u.Username] = u.Role
	}
	if roles["alice"] != "admin" {
		t.Errorf("alice role: got %q, want admin (migrated from is_admin)", roles["alice"])
	}
	if roles["bob"] != "editor" {
		t.Errorf("bob role: got %q, want editor (preserved)", roles["bob"])
	}
}

// --- helpers ---------------------------------------------------------------

func writeTempConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func readConfig(t *testing.T, path string) Config {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal: %v\ncontent: %s", err, string(data))
	}
	return cfg
}
