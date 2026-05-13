package migration_test

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"wiki-go/internal/config"
	"wiki-go/internal/migration"
)

// MigrateUserRoles unmarshals the on-disk YAML into migration.Config, mutates
// Users, then yaml.Marshal()s the whole struct back out. Any field that exists
// in the YAML but not in migration.Config is SILENTLY DROPPED on rewrite. That
// is a data-loss bug, latent because migration only triggers when a user is
// missing a Role.
//
// These tests enumerate every YAML key path reachable from config.Config and
// assert that migration.Config covers the same set, so future field additions
// to config.Config can't reintroduce drift without tripping CI.

func TestMigrationConfig_HasEveryYAMLTagInRealConfig(t *testing.T) {
	want := collectYAMLTags(reflect.TypeOf(config.Config{}))
	got := collectYAMLTags(reflect.TypeOf(migration.Config{}))

	missing := setDifference(want, got)
	if len(missing) > 0 {
		t.Errorf("migration.Config is missing %d YAML fields present in config.Config — "+
			"any of these set in the on-disk config will be silently dropped during "+
			"MigrateUserRoles. Add the matching fields to migration.Config, or rewrite "+
			"the migration to use yaml.Node so unknown content is preserved.\nmissing:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}

func TestMigrationUser_CoversEveryYAMLTagInRealUser(t *testing.T) {
	// migration.User intentionally has an extra `is_admin` field — that's the
	// legacy field the migration converts away from. Every OTHER field of
	// config.User must be present, or migration silently drops e.g. user
	// groups.
	want := collectYAMLTags(reflect.TypeOf(config.User{}))
	got := collectYAMLTags(reflect.TypeOf(migration.User{}))

	missing := setDifference(want, got)
	if len(missing) > 0 {
		t.Errorf("migration.User is missing fields from config.User — these will be "+
			"silently dropped from any user record that gets migrated.\nmissing:\n  %s",
			strings.Join(missing, "\n  "))
	}
}

// collectYAMLTags walks a struct type and returns every reachable YAML key path
// (e.g. "server.trusted_proxy_auth.user_header"). Anonymous/embedded structs
// are flattened. Fields tagged yaml:"-" are skipped (runtime-only state like
// config.Path).
func collectYAMLTags(t reflect.Type) []string {
	var out []string
	visit(t, "", &out)
	sort.Strings(out)
	return out
}

func visit(t reflect.Type, prefix string, out *[]string) {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() == reflect.Slice {
		// For []User etc., descend into the element type so user fields
		// also get drift-checked at e.g. "users.username".
		t = t.Elem()
		if t.Kind() == reflect.Ptr {
			t = t.Elem()
		}
	}
	if t.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if tag == "-" || tag == "" {
			// "" means no yaml tag (or runtime-only field) — skip.
			continue
		}
		path := tag
		if prefix != "" {
			path = prefix + "." + tag
		}
		*out = append(*out, path)
		// Recurse into nested structs / slices of structs.
		visit(f.Type, path, out)
	}
}

func setDifference(want, got []string) []string {
	have := make(map[string]struct{}, len(got))
	for _, g := range got {
		have[g] = struct{}{}
	}
	var missing []string
	for _, w := range want {
		if _, ok := have[w]; !ok {
			missing = append(missing, w)
		}
	}
	return missing
}
