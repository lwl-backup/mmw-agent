package acme

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v4/challenge/http01"
)

// WebrootProvider implements the HTTP-01 challenge using a webroot directory.
type WebrootProvider struct {
	path string
}

// NewWebrootProvider creates a new webroot provider.
func NewWebrootProvider(path string) (*WebrootProvider, error) {
	if path == "" {
		return nil, fmt.Errorf("webroot path is required")
	}

	// Ensure the webroot directory exists
	challengeDir := filepath.Join(path, http01.ChallengePath(""))
	if err := os.MkdirAll(challengeDir, 0755); err != nil {
		return nil, fmt.Errorf("create challenge directory: %w", err)
	}

	return &WebrootProvider{path: path}, nil
}

// Present writes the challenge token to the webroot directory.
func (w *WebrootProvider) Present(domain, token, keyAuth string) error {
	challengePath := filepath.Join(w.path, http01.ChallengePath(token))

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(challengePath), 0755); err != nil {
		return fmt.Errorf("create challenge directory: %w", err)
	}

	// Write the key authorization to the challenge file
	if err := os.WriteFile(challengePath, []byte(keyAuth), 0644); err != nil {
		return fmt.Errorf("write challenge file: %w", err)
	}

	return nil
}

// CleanUp removes the challenge token file.
func (w *WebrootProvider) CleanUp(domain, token, keyAuth string) error {
	challengePath := filepath.Join(w.path, http01.ChallengePath(token))
	if err := os.Remove(challengePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove challenge file: %w", err)
	}
	return nil
}
