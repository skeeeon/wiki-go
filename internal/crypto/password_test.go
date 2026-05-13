package crypto

import (
	"strings"
	"testing"
)

// Use the minimum supported bcrypt cost in tests. The production default
// (cost=14) takes hundreds of ms per hash, which is the whole point in prod
// but makes tests intolerably slow.
const testCost = 4

func TestHashPassword_RoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple", testCost)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !CheckPasswordHash("correct horse battery staple", hash) {
		t.Error("correct password should verify against its own hash")
	}
}

func TestCheckPasswordHash_RejectsWrongPassword(t *testing.T) {
	hash, err := HashPassword("right", testCost)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if CheckPasswordHash("wrong", hash) {
		t.Error("wrong password must not verify")
	}
}

func TestCheckPasswordHash_RejectsEmptyAgainstEmpty(t *testing.T) {
	// Defense-in-depth: an empty-password user record represents a
	// proxy-only user (see auth.ValidateCredentials). The hash stored for
	// such users is "" — bcrypt.CompareHashAndPassword on an empty hash
	// returns an error, so CheckPasswordHash must return false. This guards
	// against accidentally treating "" as a valid bcrypt hash.
	if CheckPasswordHash("", "") {
		t.Error("empty hash must never validate")
	}
	if CheckPasswordHash("anything", "") {
		t.Error("empty hash must never validate (non-empty password)")
	}
}

func TestCheckPasswordHash_RejectsMalformedHash(t *testing.T) {
	if CheckPasswordHash("password", "not-a-bcrypt-hash") {
		t.Error("malformed hash must not validate")
	}
}

func TestHashPassword_ProducesBcryptFormat(t *testing.T) {
	// bcrypt hashes start with $2a$, $2b$, or $2y$. We don't care which, just
	// that we're getting a recognizable bcrypt hash and not a plaintext
	// passthrough.
	hash, err := HashPassword("p", testCost)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("expected bcrypt hash prefix, got %q", hash)
	}
}

func TestHashPassword_DifferentHashEachTime(t *testing.T) {
	// bcrypt salts internally, so two hashes of the same password must differ.
	// Otherwise a leaked database would let an attacker compare hashes to
	// identify users with the same password.
	h1, err := HashPassword("same", testCost)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashPassword("same", testCost)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Error("bcrypt salts internally — two hashes of the same password must differ")
	}
	// But both must verify.
	if !CheckPasswordHash("same", h1) || !CheckPasswordHash("same", h2) {
		t.Error("both salted hashes must verify against the original password")
	}
}

func TestHashPassword_BelowMinCostSilentlyUpgraded(t *testing.T) {
	// Characterization test: bcrypt silently bumps cost values below MinCost
	// (4) up to DefaultCost (10) rather than erroring. So a misconfiguration
	// like `passwordstrength: 2` in config.yaml does NOT produce an error —
	// it produces a hash at cost=10. Verify both sides:
	//   1. No error returned
	//   2. Hashing/verifying still works
	// If golang.org/x/crypto/bcrypt ever changes this behavior, this test
	// fires and we get to make a deliberate decision.
	hash, err := HashPassword("p", 1)
	if err != nil {
		t.Fatalf("expected silent upgrade, got error: %v", err)
	}
	if !CheckPasswordHash("p", hash) {
		t.Error("silently-upgraded hash should still verify")
	}
}

func TestHashPassword_CostAboveMaxErrors(t *testing.T) {
	// bcrypt's MaxCost is 31; values above this return InvalidCostError.
	// This is the actual error path for cost misconfiguration.
	if _, err := HashPassword("p", 32); err == nil {
		t.Error("expected error for cost above bcrypt maximum")
	}
}
