package auth

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// SessionStore manages session persistence
type SessionStore struct {
	mu       sync.RWMutex
	filePath string
}

// NewSessionStore creates a new session store
func NewSessionStore(filePath string) *SessionStore {
	// Ensure directory exists
	if dir := filepath.Dir(filePath); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			log.Printf("Error creating session store directory: %v", err)
		}
	}

	return &SessionStore{
		filePath: filePath,
	}
}

// SaveSessions saves the sessions to disk
func (s *SessionStore) SaveSessions(sessions map[string]Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create a temporary file
	tempFile := s.filePath + ".tmp"
	f, err := os.OpenFile(tempFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}

	// Encode sessions to JSON
	encoder := json.NewEncoder(f)
	if err := encoder.Encode(sessions); err != nil {
		f.Close()
		return err
	}
	f.Close()

	// Rename temporary file to actual file (atomic operation)
	if err := os.Rename(tempFile, s.filePath); err != nil {
		return err
	}

	return nil
}

// LoadSessions loads sessions from disk
func (s *SessionStore) LoadSessions() (map[string]Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sessions := make(map[string]Session)

	// Check if file exists
	if _, err := os.Stat(s.filePath); os.IsNotExist(err) {
		return sessions, nil
	}

	// Read file
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return nil, err
	}

	// Decode JSON
	if err := json.Unmarshal(data, &sessions); err != nil {
		// If file is corrupted, return empty map and log error
		log.Printf("Error decoding session file: %v", err)
		return sessions, nil
	}

	return sessions, nil
}
