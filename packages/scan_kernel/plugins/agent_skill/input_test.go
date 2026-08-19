package agentskill

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
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

func TestSelectComponentsUsesSpecificationSkillRootsAndReadmePolicy(t *testing.T) {
	all := []component{
		{Path: "README.md"},
		{Path: "tooling.go"},
		{Path: "skills/alpha/SKILL.md", Content: "---\nname: alpha\n---\n"},
		{Path: "skills/alpha/README.MD"},
		{Path: "skills/alpha/scripts/run.py"},
		{Path: "custom/beta/SKILL.md", Content: "---\nname: beta\n---\n"},
		{Path: "custom/beta/references/REFERENCE.md"},
	}

	paths := func(items []component) []string {
		result := make([]string, 0, len(items))
		for _, item := range items {
			result = append(result, item.Path)
		}
		return result
	}

	files, skills, err := selectComponents(all, "skill_files", false)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"skills/alpha/SKILL.md", "custom/beta/SKILL.md"}; !reflect.DeepEqual(paths(files), want) {
		t.Fatalf("skill_files=%v, want %v", paths(files), want)
	}
	if len(skills) != 2 {
		t.Fatalf("skills=%d, want 2", len(skills))
	}

	folders, _, err := selectComponents(all, "skill_folders", false)
	if err != nil {
		t.Fatal(err)
	}
	wantFolders := []string{"skills/alpha/SKILL.md", "skills/alpha/scripts/run.py", "custom/beta/SKILL.md", "custom/beta/references/REFERENCE.md"}
	if !reflect.DeepEqual(paths(folders), wantFolders) {
		t.Fatalf("skill_folders=%v, want %v", paths(folders), wantFolders)
	}

	repository, _, err := selectComponents(all, "repository", false)
	if err != nil {
		t.Fatal(err)
	}
	wantRepository := []string{"tooling.go", "skills/alpha/SKILL.md", "skills/alpha/scripts/run.py", "custom/beta/SKILL.md", "custom/beta/references/REFERENCE.md"}
	if !reflect.DeepEqual(paths(repository), wantRepository) {
		t.Fatalf("repository=%v, want %v", paths(repository), wantRepository)
	}

	withReadme, _, err := selectComponents(all, "skill_folders", true)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"skills/alpha/SKILL.md", "skills/alpha/README.MD", "skills/alpha/scripts/run.py", "custom/beta/SKILL.md", "custom/beta/references/REFERENCE.md"}; !reflect.DeepEqual(paths(withReadme), want) {
		t.Fatalf("with README=%v, want %v", paths(withReadme), want)
	}
}

func TestSelectComponentsRejectsMissingManifestAndInvalidReadmeCombination(t *testing.T) {
	all := []component{{Path: "README.md"}}
	if _, _, err := selectComponents(all, "skill_folders", false); err == nil {
		t.Fatal("expected missing SKILL.md to fail")
	}
	if _, _, err := selectComponents(all, "skill_files", true); err == nil {
		t.Fatal("expected include_readme with skill_files to fail")
	}
}
