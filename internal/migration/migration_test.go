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
