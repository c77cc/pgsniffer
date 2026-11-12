package e2e

import (
	"os"
	"path/filepath"
)

func artifactBase(repo, configured string) string {
	if configured == "" {
		return os.TempDir()
	}
	if filepath.IsAbs(configured) {
		return filepath.Clean(configured)
	}
	return filepath.Join(repo, configured)
}
