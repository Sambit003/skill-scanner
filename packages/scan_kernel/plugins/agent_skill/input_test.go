package agentskill

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveTargetCanonicalizesRootBeforeCheckingContainedSymlinks(t *testing.T) {
	base := t.TempDir()
	physicalRoot := filepath.Join(base, "physical")
	if err := os.Mkdir(physicalRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(physicalRoot, "CLAUDE.md"), []byte("persist state across sessions"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("CLAUDE.md", filepath.Join(physicalRoot, "AGENTS.md")); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	aliasedRoot := filepath.Join(base, "alias")
	if err := os.Symlink(physicalRoot, aliasedRoot); err != nil {
		t.Skipf("directory symlinks are unavailable: %v", err)
	}

	root, sourceType, tempDir, err := resolveTarget(context.Background(), aliasedRoot, true)
	if err != nil {
		t.Fatal(err)
	}
	if tempDir != "" || sourceType != "directory" {
		t.Fatalf("source=(%q, %q), want directory without temporary storage", sourceType, tempDir)
	}
	wantRoot, err := filepath.EvalSymlinks(physicalRoot)
	if err != nil {
		t.Fatal(err)
	}
	if root != wantRoot {
		t.Fatalf("root=%q, want canonical root %q", root, wantRoot)
	}

	components, _, err := readComponents(root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"AGENTS.md": false, "CLAUDE.md": false}
	for _, item := range components {
		if _, ok := want[item.Path]; ok {
			want[item.Path] = true
		}
	}
	for path, found := range want {
		if !found {
			t.Errorf("missing contained component %s: %#v", path, components)
		}
	}
}
