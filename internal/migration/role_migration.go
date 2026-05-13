package migration

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"
	"wiki-go/internal/roles"

	"gopkg.in/yaml.v3"
)

// User mirrors config.User plus the legacy IsAdmin field. The mirror exists
// because MigrateUserRoles round-trips the config through yaml.Marshal — any
// field present on disk but missing from this struct would be silently
// dropped on rewrite. drift_test.go enforces this stays in sync.
type User struct {
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	Role     string   `yaml:"role"`     // "admin", "editor", or "viewer"
	Groups   []string `yaml:"groups,omitempty"`
	IsAdmin  bool     `yaml:"is_admin,omitempty"` // legacy field this migration converts away from
}

// AccessRule mirrors config.AccessRule. Same reason as above.
type AccessRule struct {
	Pattern     string   `yaml:"pattern"`
	Access      string   `yaml:"access"`
	Groups      []string `yaml:"groups,omitempty"`
	Description string   `yaml:"description,omitempty"`
}

// TrustedProxyAuthConfig mirrors config.TrustedProxyAuthConfig.
type TrustedProxyAuthConfig struct {
	Enabled         bool     `yaml:"enabled"`
	UserHeader      string   `yaml:"user_header"`
	EmailHeader     string   `yaml:"email_header"`
	GroupsHeader    string   `yaml:"groups_header"`
	GroupsDelimiter string   `yaml:"groups_delimiter"`
	DefaultRole     string   `yaml:"default_role"`
	AutoCreateUsers bool     `yaml:"auto_create_users"`
	LogoutURL       string   `yaml:"logout_url"`
	TrustedCIDRs    []string `yaml:"trusted_cidrs,omitempty"`
}

// Config mirrors config.Config so the migration's read/modify/write cycle is
// lossless. We don't use this struct for anything other than YAML
// passthrough; the migration only touches Users.
type Config struct {
	Server struct {
		Host                 string                 `yaml:"host"`
		Port                 int                    `yaml:"port"`
		AllowInsecureCookies bool                   `yaml:"allow_insecure_cookies"`
		SSL                  bool                   `yaml:"ssl"`
		SSLCert              string                 `yaml:"ssl_cert"`
		SSLKey               string                 `yaml:"ssl_key"`
		TrustedProxyAuth     TrustedProxyAuthConfig `yaml:"trusted_proxy_auth"`
	} `yaml:"server"`
	Wiki struct {
		RootDir                     string `yaml:"root_dir"`
		DocumentsDir                string `yaml:"documents_dir"`
		Title                       string `yaml:"title"`
		Owner                       string `yaml:"owner"`
		Notice                      string `yaml:"notice"`
		Timezone                    string `yaml:"timezone"`
		Private                     bool   `yaml:"private"`
		DisableComments             bool   `yaml:"disable_comments"`
		DisableFileUploadChecking   bool   `yaml:"disable_file_upload_checking"`
		EnableLinkEmbedding         bool   `yaml:"enable_link_embedding"`
		HideAttachments             bool   `yaml:"hide_attachments"`
		DisableContentMaxWidth      bool   `yaml:"disable_content_max_width"`
		AlwaysOpenChildrenInSidebar bool   `yaml:"always_open_children_in_sidebar"`
		MaxVersions                 int    `yaml:"max_versions"`
		MaxUploadSize               int    `yaml:"max_upload_size"`
		Language                    string `yaml:"language"`
	} `yaml:"wiki"`
	Users       []User       `yaml:"users"`
	AccessRules []AccessRule `yaml:"access_rules,omitempty"`
	Security    struct {
		PasswordStrength int `yaml:"passwordstrength"`
		LoginBan         struct {
			Enabled           bool `yaml:"enabled"`
			MaxFailures       int  `yaml:"max_failures"`
			WindowSeconds     int  `yaml:"window_seconds"`
			InitialBanSeconds int  `yaml:"initial_ban_seconds"`
			MaxBanSeconds     int  `yaml:"max_ban_seconds"`
		} `yaml:"login_ban"`
	} `yaml:"security"`
}

// copyFile creates a copy of src file at dst path
func copyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}

// MigrateUserRoles updates the user configuration from the old IsAdmin boolean
// to the new role-based system. This function should be called during application
// startup to ensure all users have a proper role assigned.
func MigrateUserRoles(configPath string) error {
	log.Println("Checking if user role migration is needed...")

	// Read the config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Config file does not exist yet – nothing to migrate. It will be
			// created with defaults when the main application loads the config.
			log.Printf("Config file %s not found, skipping user-role migration", configPath)
			return nil
		}
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse the config
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	migrationNeeded := false

	// Check if any users need migration (empty Role or has IsAdmin field)
	for _, user := range cfg.Users {
		if user.Role == "" || user.IsAdmin {
			migrationNeeded = true
			break
		}
	}

	if !migrationNeeded {
		log.Println("No role migration needed, all users have roles assigned")
		return nil
	}

	// Create backup of config file before migration (only if migration is needed)
	backupPath := configPath + "." + time.Now().Format("20060102-150405") + ".bak"
	if err := copyFile(configPath, backupPath); err != nil {
		return fmt.Errorf("failed to create config backup: %w", err)
	}
	log.Printf("Created config backup at: %s", backupPath)

	log.Println("Migrating users from IsAdmin to role-based system...")

	// Create a new users slice to hold the migrated users
	migratedUsers := make([]User, 0, len(cfg.Users))

	// Migrate each user
	for _, user := range cfg.Users {
		// If role is already set and no IsAdmin field, keep it
		if user.Role != "" && !user.IsAdmin {
			migratedUsers = append(migratedUsers, user)
			continue
		}

		// Set role based on IsAdmin field if present
		if user.IsAdmin {
			user.Role = roles.RoleAdmin
		} else {
			user.Role = roles.RoleViewer
		}

		// Clear the IsAdmin field after migration
		user.IsAdmin = false

		migratedUsers = append(migratedUsers, user)
		log.Printf("Migrated user %s: Role=%s", user.Username, user.Role)
	}

	// Update the config with migrated users
	cfg.Users = migratedUsers

	// Save the updated config
	updatedData, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal updated config: %w", err)
	}

	if err := os.WriteFile(configPath, updatedData, 0644); err != nil {
		return fmt.Errorf("failed to save migrated config: %w", err)
	}

	log.Println("User role migration completed successfully")
	return nil
}
