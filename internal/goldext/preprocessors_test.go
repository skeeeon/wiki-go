package goldext

import (
	"regexp"
	"strings"
	"testing"
)

// Characterization tests for the high-value preprocessors. The point of these
// tests is NOT to prove the preprocessors are correct — they exist mostly to
// lock down current behavior so the next reorder of the chain (or refactor of
// an individual preprocessor) produces a visible diff instead of silently
// breaking page rendering.

// --- Subscript --------------------------------------------------------------

func TestSubscriptPreprocessor(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"basic subscript", "H~2~O", "H<sub>2</sub>O"},
		{"multiple subscripts on a line", "C~6~H~12~O~6~", "C<sub>6</sub>H<sub>12</sub>O<sub>6</sub>"},
		{
			"double tilde is strikethrough, not subscript",
			"~~struck through~~",
			"~~struck through~~",
		},
		{
			"mixed strikethrough and subscript",
			"~~old~~ value is H~2~O",
			"~~old~~ value is H<sub>2</sub>O",
		},
		{
			"unclosed single tilde passes through",
			"a ~ b",
			"a ~ b",
		},
		{
			"subscript inside inline code is left alone",
			"`H~2~O` as code, H~2~O outside",
			"`H~2~O` as code, H<sub>2</sub>O outside",
		},
		{
			"fenced code block contents are skipped entirely",
			"before\n```\nH~2~O\n```\nafter ~x~",
			"before\n```\nH~2~O\n```\nafter <sub>x</sub>",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SubscriptPreprocessor(tc.in, "")
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// --- Frontmatter ------------------------------------------------------------

func TestFrontmatterPreprocessor_StripsLeadingBlock(t *testing.T) {
	in := "---\nlayout: kanban\n---\n# Title\n\nbody"
	got := FrontmatterPreprocessor(in, "")
	if got != "# Title\n\nbody" {
		t.Errorf("got %q, want stripped content", got)
	}
}

func TestFrontmatterPreprocessor_LeavesContentWithoutFrontmatter(t *testing.T) {
	in := "# Title\n\nplain body"
	got := FrontmatterPreprocessor(in, "")
	if got != in {
		t.Errorf("content without frontmatter must pass through unchanged; got %q", got)
	}
}

func TestFrontmatterPreprocessor_LeavesUnclosedBlockAlone(t *testing.T) {
	// Unclosed frontmatter is not a delimiter — must not consume the
	// whole document. Verified more thoroughly in frontmatter package
	// tests; this is the contract from the preprocessor's POV.
	in := "---\nlayout: kanban\nno close\nbody"
	got := FrontmatterPreprocessor(in, "")
	if got != in {
		t.Errorf("unclosed frontmatter must pass through unchanged; got %q", got)
	}
}

// --- Emoji ------------------------------------------------------------------

func TestEmojiPreprocessor_ReplacesKnownShortcodes(t *testing.T) {
	// emoji map is populated from an embedded JSON file at package init.
	// :smile: is one of the most stable entries — if it ever doesn't resolve,
	// either the data file is missing or init() broke. Don't pin to an exact
	// codepoint because emoji JSON can shift, just verify the shortcode was
	// substituted.
	if _, ok := emojis[":smile:"]; !ok {
		t.Skip("emoji data not loaded in this environment, skipping")
	}
	got := EmojiPreprocessor("hello :smile: world", "")
	if strings.Contains(got, ":smile:") {
		t.Errorf(":smile: should have been replaced; got %q", got)
	}
	if !strings.Contains(got, emojis[":smile:"]) {
		t.Errorf("expected %q in output; got %q", emojis[":smile:"], got)
	}
}

func TestEmojiPreprocessor_LeavesShortcodesInCodeBlocks(t *testing.T) {
	if _, ok := emojis[":smile:"]; !ok {
		t.Skip("emoji data not loaded")
	}
	in := "before :smile:\n```\n:smile: in code\n```\nafter :smile:"
	got := EmojiPreprocessor(in, "")

	// Lines outside the fence: substituted.
	if strings.Count(got, ":smile:") != 1 {
		t.Errorf("expected exactly one untouched :smile: (inside code block); got %q", got)
	}
	// Inside the fence: literal :smile: preserved.
	if !strings.Contains(got, ":smile: in code") {
		t.Errorf(":smile: inside ```fence``` should be preserved; got %q", got)
	}
}

func TestEmojiPreprocessor_UnknownShortcodePassesThrough(t *testing.T) {
	got := EmojiPreprocessor("hello :not-a-real-emoji-xyz:", "")
	if !strings.Contains(got, ":not-a-real-emoji-xyz:") {
		t.Errorf("unknown shortcode should pass through unchanged; got %q", got)
	}
}

// --- Shortcodes (:::year:::, :::stats:::) ----------------------------------

func TestShortcodesPreprocessor_YearReplacement(t *testing.T) {
	got := ShortcodesPreprocessor("Copyright :::year::: All rights reserved.", "")
	// Don't pin to the current year — that would make the test break on
	// New Year's Eve. Just assert ":::year:::" was substituted with 4 digits.
	if strings.Contains(got, ":::year:::") {
		t.Errorf(":::year::: should have been replaced; got %q", got)
	}
	if !regexp.MustCompile(`Copyright \d{4} All rights reserved\.`).MatchString(got) {
		t.Errorf("expected a 4-digit year substitution; got %q", got)
	}
}

func TestShortcodesPreprocessor_ShortcodesInCodeBlocksAreLeftAlone(t *testing.T) {
	// Critical safety property: a user documenting `:::year:::` syntax in a
	// fenced block must NOT have it substituted, or the docs become wrong.
	in := "Outside :::year::: still here.\n```\nUse :::year::: in your config\n```"
	got := ShortcodesPreprocessor(in, "")
	if !strings.Contains(got, "Use :::year::: in your config") {
		t.Errorf(":::year::: inside fenced block must be preserved; got %q", got)
	}
	// And the outside one must still be replaced.
	if strings.Contains(strings.SplitN(got, "```", 2)[0], ":::year:::") {
		t.Errorf("outside-of-code :::year::: should still be substituted; got %q", got)
	}
}

func TestShortcodesPreprocessor_InlineCodePreservesShortcodes(t *testing.T) {
	in := "Use `:::year:::` to insert the current year (e.g. :::year:::)."
	got := ShortcodesPreprocessor(in, "")
	// Backtick-quoted version is preserved literally.
	if !strings.Contains(got, "`:::year:::`") {
		t.Errorf("inline code :::year::: must be preserved; got %q", got)
	}
	// Parenthesized version is substituted.
	if !regexp.MustCompile(`e\.g\. \d{4}\)`).MatchString(got) {
		t.Errorf("expected substitution outside inline code; got %q", got)
	}
}

// --- Mermaid ----------------------------------------------------------------

func TestMermaidPreprocessor_ExtractsBlockToPlaceholder(t *testing.T) {
	in := "before\n```mermaid\ngraph TD\nA-->B\n```\nafter"
	got := MermaidPreprocessor(in, "")

	// The fenced mermaid block is extracted to a placeholder so Goldmark
	// won't mangle the diagram source. RestoreMermaidBlocks puts it back.
	if !strings.Contains(got, "<!-- MERMAID_BLOCK_") {
		t.Errorf("expected placeholder comment; got %q", got)
	}
	if strings.Contains(got, "graph TD") {
		t.Errorf("mermaid source must not be left in the markdown stream; got %q", got)
	}
	// Verify the round-trip restores the diagram in HTML form.
	restored := RestoreMermaidBlocks(got)
	if !strings.Contains(restored, `<div class="mermaid">`) {
		t.Errorf("expected mermaid div in restored output; got %q", restored)
	}
	if !strings.Contains(restored, "graph TD") || !strings.Contains(restored, "A-->B") {
		t.Errorf("restored output should contain original diagram source; got %q", restored)
	}
}

func TestMermaidPreprocessor_NoMermaidIsPassThrough(t *testing.T) {
	in := "regular markdown\n\nwith no diagrams"
	got := MermaidPreprocessor(in, "")
	if got != in {
		t.Errorf("input without ```mermaid blocks should be unchanged; got %q", got)
	}
}

func TestMermaidPreprocessor_TildeFenceAlsoWorks(t *testing.T) {
	// Goldmark supports both ``` and ~~~ as fence delimiters. The preprocessor
	// must handle both so users can pick either style.
	in := "~~~mermaid\ngraph LR\nA-->B\n~~~"
	got := MermaidPreprocessor(in, "")
	if !strings.Contains(got, "<!-- MERMAID_BLOCK_") {
		t.Errorf("tilde-fenced mermaid should also be extracted; got %q", got)
	}
}

// --- ExtractYouTubeID (pure helper) ----------------------------------------

func TestExtractYouTubeID(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"watch URL", "https://www.youtube.com/watch?v=dQw4w9WgXcQ", "dQw4w9WgXcQ"},
		{"short youtu.be URL", "https://youtu.be/dQw4w9WgXcQ", "dQw4w9WgXcQ"},
		{"embed URL", "https://www.youtube.com/embed/dQw4w9WgXcQ", "dQw4w9WgXcQ"},
		{"old /v/ URL", "https://www.youtube.com/v/dQw4w9WgXcQ", "dQw4w9WgXcQ"},
		{"strips query params after ID", "https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=42s", "dQw4w9WgXcQ"},
		{"bare ID passes through", "dQw4w9WgXcQ", "dQw4w9WgXcQ"},
		{"unrelated URL returns empty", "https://example.com/video", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExtractYouTubeID(tc.in); got != tc.want {
				t.Errorf("ExtractYouTubeID(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
