package auth

import (
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"wiki-go/internal/config"
)

// proxyAuthState holds pre-parsed configuration so we don't re-parse on every request.
type proxyAuthState struct {
	enabled     bool
	cfg         *config.Config
	trustedNets []*net.IPNet
}

// TrustedProxyAuthMiddleware returns an http.Handler that reads identity from
// trusted proxy headers (e.g. oauth2-proxy) and creates Wiki-Go sessions
// automatically. If the feature is disabled or the header is absent, the
// request falls through to normal authentication.
func TrustedProxyAuthMiddleware(cfg *config.Config, next http.Handler) http.Handler {
	tpa := &cfg.Server.TrustedProxyAuth
	if !tpa.Enabled {
		return next // no-op wrapper
	}

	state := &proxyAuthState{
		enabled:     true,
		cfg:         cfg,
		trustedNets: parseCIDRs(tpa.TrustedCIDRs),
	}

	log.Printf("Trusted proxy auth enabled (user header: %s, groups header: %s, default role: %s)",
		tpa.UserHeader, tpa.GroupsHeader, tpa.DefaultRole)

	if len(state.trustedNets) > 0 {
		log.Printf("Trusted proxy auth restricted to CIDRs: %v", tpa.TrustedCIDRs)
	} else {
		log.Println("WARNING: Trusted proxy auth has no trusted_cidrs configured — any source can set auth headers. " +
			"Ensure Wiki-Go is not directly reachable by clients.")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleProxyAuth(state, w, r, next)
	})
}

func handleProxyAuth(state *proxyAuthState, w http.ResponseWriter, r *http.Request, next http.Handler) {
	tpa := &state.cfg.Server.TrustedProxyAuth

	// If user already has a valid session, skip proxy header processing.
	if existing := GetSession(r); existing != nil {
		next.ServeHTTP(w, r)
		return
	}

	// Read the identity header.
	username := strings.TrimSpace(r.Header.Get(tpa.UserHeader))
	if username == "" {
		// No proxy identity present — fall through to normal auth.
		next.ServeHTTP(w, r)
		return
	}

	// Validate source IP against trusted CIDRs if configured.
	if len(state.trustedNets) > 0 && !isFromTrustedSource(r, state.trustedNets) {
		log.Printf("WARNING: Proxy auth header from untrusted source %s for user %q — ignoring",
			r.RemoteAddr, username)
		// Strip the auth headers so downstream doesn't see them.
		r.Header.Del(tpa.UserHeader)
		r.Header.Del(tpa.EmailHeader)
		r.Header.Del(tpa.GroupsHeader)
		next.ServeHTTP(w, r)
		return
	}

	// Resolve role and groups for this user.
	role, groups := resolveProxyRoleAndGroups(username, r, state.cfg)

	// Create a Wiki-Go session (sets cookies on the response).
	if err := CreateSession(w, username, role, groups, false, state.cfg); err != nil {
		log.Printf("Error creating proxy auth session for %q: %v", username, err)
		next.ServeHTTP(w, r)
		return
	}

	// Auto-create user in config if enabled and user doesn't exist yet.
	if tpa.AutoCreateUsers {
		ensureProxyUserExists(username, role, groups, state.cfg)
	}

	next.ServeHTTP(w, r)
}

// resolveProxyRoleAndGroups determines the role and groups for a proxy-authenticated user.
// Users already defined in config.yaml take precedence (allowing admins to pre-assign roles).
// Groups from the proxy header are merged with any groups defined in config.
func resolveProxyRoleAndGroups(username string, r *http.Request, cfg *config.Config) (string, []string) {
	tpa := &cfg.Server.TrustedProxyAuth

	// Parse groups from proxy header.
	var proxyGroups []string
	if gh := r.Header.Get(tpa.GroupsHeader); gh != "" {
		delim := tpa.GroupsDelimiter
		if delim == "" {
			delim = ","
		}
		for _, g := range strings.Split(gh, delim) {
			g = strings.TrimSpace(g)
			if g != "" {
				proxyGroups = append(proxyGroups, g)
			}
		}
	}

	// Check if user already exists in config (manual role override).
	for _, user := range cfg.Users {
		if user.Username == username {
			merged := mergeUniqueStrings(user.Groups, proxyGroups)
			role := user.Role
			if role == "" {
				role = tpa.DefaultRole
			}
			return role, merged
		}
	}

	// User not in config — use default role.
	return tpa.DefaultRole, proxyGroups
}

// ensureProxyUserExists adds a proxy-authenticated user to cfg.Users if they don't
// already exist. The user is created with an empty password (no local login possible).
// The config file is persisted to disk so the user appears in the admin panel.
var proxyUserMu sync.Mutex

func ensureProxyUserExists(username, role string, groups []string, cfg *config.Config) {
	proxyUserMu.Lock()
	defer proxyUserMu.Unlock()

	for _, u := range cfg.Users {
		if u.Username == username {
			return // already exists
		}
	}

	cfg.Users = append(cfg.Users, config.User{
		Username: username,
		Password: "", // empty = proxy-only, no local login
		Role:     role,
		Groups:   groups,
	})

	// Persist to disk. We use a fire-and-forget approach here; failure to
	// persist is logged but doesn't block the request. The user will be
	// re-created on next login if persistence failed.
	go func() {
		f, err := os.Create(config.ConfigFilePath)
		if err != nil {
			log.Printf("Warning: failed to persist auto-created proxy user %q: %v", username, err)
			return
		}
		defer f.Close()
		if err := config.SaveConfig(cfg, f); err != nil {
			log.Printf("Warning: failed to save config after auto-creating proxy user %q: %v", username, err)
		}
	}()
}

// --- helpers ---

func parseCIDRs(cidrs []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("Warning: invalid trusted CIDR %q: %v", cidr, err)
			continue
		}
		nets = append(nets, network)
	}
	return nets
}

func isFromTrustedSource(r *http.Request, trusted []*net.IPNet) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr might not have a port (unlikely but handle gracefully).
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, network := range trusted {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func mergeUniqueStrings(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	var result []string
	for _, s := range a {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	for _, s := range b {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}