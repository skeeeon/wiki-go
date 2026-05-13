package frontmatter

import (
	"strings"
	"testing"
)

func TestParse_NoFrontmatter(t *testing.T) {
	in := "# Hello\n\nbody here"
	meta, rest, ok := Parse(in)
	if ok {
		t.Error("expected ok=false for content without frontmatter")
	}
	if rest != in {
		t.Errorf("content should be returned unchanged when no frontmatter; got %q", rest)
	}
	if meta.Layout != "" {
		t.Errorf("metadata should be zero-valued; got %+v", meta)
	}
}

func TestParse_ValidFrontmatter(t *testing.T) {
	in := "---\nlayout: kanban\n---\n# Title\n\nbody"
	meta, rest, ok := Parse(in)
	if !ok {
		t.Fatal("expected ok=true for valid frontmatter")
	}
	if meta.Layout != "kanban" {
		t.Errorf("layout: got %q, want kanban", meta.Layout)
	}
	if rest != "# Title\n\nbody" {
		t.Errorf("body: got %q, want stripped content", rest)
	}
}

func TestParse_UnclosedFrontmatterTreatedAsPlainContent(t *testing.T) {
	// "---\nlayout: kanban\n" with no closing "\n---" — must NOT consume the
	// rest of the document as frontmatter; instead, return the whole thing
	// as content.
	in := "---\nlayout: kanban\nbut never closed"
	meta, rest, ok := Parse(in)
	if ok {
		t.Error("expected ok=false for unclosed frontmatter")
	}
	if rest != in {
		t.Errorf("content should pass through verbatim; got %q", rest)
	}
	if meta.Layout != "" {
		t.Errorf("metadata should be zero-valued; got %+v", meta)
	}
}

func TestParse_MalformedYAMLFallsBack(t *testing.T) {
	// Closing delimiter present but the YAML is invalid. The function
	// returns ok=false and leaves content unchanged — graceful degradation
	// rather than failing the page render.
	in := "---\nlayout: [unclosed-list\n---\n# body"
	meta, rest, ok := Parse(in)
	if ok {
		t.Error("expected ok=false for malformed YAML")
	}
	if rest != in {
		t.Errorf("content should pass through verbatim; got %q", rest)
	}
	if meta.Layout != "" {
		t.Errorf("metadata should be zero-valued; got %+v", meta)
	}
}

func TestParse_EmptyFrontmatter(t *testing.T) {
	// Valid empty frontmatter block — should succeed with zero metadata.
	in := "---\n\n---\n# body"
	meta, rest, ok := Parse(in)
	if !ok {
		t.Fatal("expected ok=true for empty frontmatter")
	}
	if meta.Layout != "" {
		t.Errorf("layout should be empty, got %q", meta.Layout)
	}
	if rest != "# body" {
		t.Errorf("body: got %q, want '# body'", rest)
	}
}

func TestParse_StripsLeadingNewlinesAfterFrontmatter(t *testing.T) {
	// The closing "---" is followed by multiple blank lines — Parse should
	// trim them so the body doesn't start with whitespace that would mess
	// with downstream Markdown rendering.
	in := "---\nlayout: x\n---\n\n\n\nbody"
	_, rest, ok := Parse(in)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if rest != "body" {
		t.Errorf("body: got %q, want 'body' (leading newlines stripped)", rest)
	}
}

func TestParse_RequiresNewlineAfterOpeningDelimiter(t *testing.T) {
	// "---" without a following newline is just a horizontal rule, not
	// frontmatter. The parser keys on "---\n" specifically.
	in := "---layout: x\n---\nbody"
	_, rest, ok := Parse(in)
	if ok {
		t.Error("expected ok=false when opening delimiter lacks newline")
	}
	if rest != in {
		t.Errorf("content should pass through; got %q", rest)
	}
}

// --- HasFrontmatter / Extract -------------------------------------------

func TestHasFrontmatter(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"has frontmatter", "---\nlayout: x\n---\nbody", true},
		{"no frontmatter", "body only", false},
		{"unclosed", "---\nlayout: x\nbody", false},
		{"empty string", "", false},
		{"just dashes", "---", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasFrontmatter(tc.in); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	got := Extract("---\nlayout: kanban\n---\nbody")
	if got != "layout: kanban" {
		t.Errorf("Extract: got %q, want 'layout: kanban'", got)
	}
	if Extract("no frontmatter here") != "" {
		t.Error("Extract on plain content should return empty string")
	}
	if Extract("---\nunclosed") != "" {
		t.Error("Extract on unclosed frontmatter should return empty string")
	}
}

// --- Add: round-trip ------------------------------------------------------

func TestAdd_AddsToPlainContent(t *testing.T) {
	out, err := Add("# Title\n\nbody", Metadata{Layout: "links"})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !strings.HasPrefix(out, "---\n") {
		t.Errorf("output should start with frontmatter delimiter; got %q", out)
	}
	meta, rest, ok := Parse(out)
	if !ok {
		t.Fatal("Add output must be re-parseable")
	}
	if meta.Layout != "links" {
		t.Errorf("layout: got %q, want links", meta.Layout)
	}
	if rest != "# Title\n\nbody" {
		t.Errorf("body should round-trip unchanged; got %q", rest)
	}
}

func TestAdd_ReplacesExistingFrontmatter(t *testing.T) {
	in := "---\nlayout: kanban\n---\n# Title"
	out, err := Add(in, Metadata{Layout: "links"})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	meta, rest, ok := Parse(out)
	if !ok {
		t.Fatal("output must be parseable")
	}
	if meta.Layout != "links" {
		t.Errorf("layout: got %q, want links (existing frontmatter should be replaced)", meta.Layout)
	}
	if rest != "# Title" {
		t.Errorf("body: got %q, want '# Title'", rest)
	}
}
