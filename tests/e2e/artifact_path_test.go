package e2e

import (
	"path/filepath"
	"testing"
)

func TestArtifactBase(t *testing.T) {
	repo := filepath.Join(string(filepath.Separator), "workspace", "pgsniffer")

	t.Run("relative paths use repository root", func(t *testing.T) {
		got := artifactBase(repo, filepath.Join(".artifacts", "e2e", "postgres-16"))
		want := filepath.Join(repo, ".artifacts", "e2e", "postgres-16")
		if got != want {
			t.Fatalf("artifactBase() = %q, want %q", got, want)
		}
	})

	t.Run("absolute paths remain absolute", func(t *testing.T) {
		configured := filepath.Join(string(filepath.Separator), "tmp", "pgsniffer-e2e")
		if got := artifactBase(repo, configured); got != configured {
			t.Fatalf("artifactBase() = %q, want %q", got, configured)
		}
	})
}
