package agentskill

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	git "github.com/go-git/go-git/v5"
)

const (
	maxFileBytes      = 1_000_000
	maxDownloadBytes  = 100 * 1024 * 1024
	maxArchiveBytes   = 250 * 1024 * 1024
	maxArchiveMembers = 10_000
)

var allowedGitHosts = map[string]bool{"github.com": true, "gitlab.com": true, "bitbucket.org": true}
var allowedDownloadHosts = map[string]bool{
	"github.com": true, "raw.githubusercontent.com": true, "gitlab.com": true,
	"bitbucket.org": true, "huggingface.co": true,
}

type component struct {
	Path       string `json:"path"`
	Type       string `json:"type"`
	Lines      int    `json:"lines"`
	Executable bool   `json:"executable"`
	SizeBytes  int    `json:"size_bytes"`
	Content    string `json:"-"`
}

type preparedInput struct {
	Root       string
	SourceType string
	TempDir    string
	Components []component
	Manifest   map[string]any
}

func (p *preparedInput) cleanup() {
	if p.TempDir != "" {
		_ = os.RemoveAll(p.TempDir)
	}
}

func prepare(ctx context.Context, target string, offline bool) (*preparedInput, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("target must not be empty")
	}
	root, sourceType, tempDir, err := resolveTarget(ctx, target, offline)
	if err != nil {
		return nil, err
	}
	prepared := &preparedInput{Root: root, SourceType: sourceType, TempDir: tempDir}
	prepared.Components, prepared.Manifest, err = readComponents(root)
	if err != nil {
		prepared.cleanup()
		return nil, err
	}
	return prepared, nil
}

func resolveTarget(ctx context.Context, target string, offline bool) (string, string, string, error) {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		if offline {
			return "", "", "", errors.New("remote targets are disabled in offline mode")
		}
		parsed, err := url.Parse(target)
		if err != nil {
			return "", "", "", err
		}
		if parsed.Scheme != "https" {
			return "", "", "", errors.New("remote targets must use HTTPS")
		}
		if parsed.User != nil {
			return "", "", "", errors.New("remote target URLs must not contain credentials")
		}
		host := strings.ToLower(parsed.Hostname())
		if looksLikeGitURL(parsed) {
			if err := validateRemoteHost(ctx, host, allowedGitHosts); err != nil {
				return "", "", "", err
			}
			tempDir, err := makeTempDir()
			if err != nil {
				return "", "", "", err
			}
			repoDir := filepath.Join(tempDir, "repo")
			_, err = git.PlainCloneContext(ctx, repoDir, false, &git.CloneOptions{URL: target, Depth: 1, SingleBranch: true})
			if err != nil {
				_ = os.RemoveAll(tempDir)
				return "", "", "", fmt.Errorf("clone repository: %w", err)
			}
			return repoDir, "git", tempDir, nil
		}
		if err := validateRemoteHost(ctx, host, allowedDownloadHosts); err != nil {
			return "", "", "", err
		}
		return download(ctx, target)
	}

	info, err := os.Stat(target)
	if err != nil {
		return "", "", "", fmt.Errorf("target not found: %s", target)
	}
	absolute, err := filepath.Abs(target)
	if err != nil {
		return "", "", "", err
	}
	absolute, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", "", "", fmt.Errorf("resolve target path: %w", err)
	}
	if info.IsDir() {
		return absolute, "directory", "", nil
	}
	if strings.EqualFold(filepath.Ext(target), ".zip") {
		return extractZip(absolute, "")
	}
	tempDir, err := makeTempDir()
	if err != nil {
		return "", "", "", err
	}
	destination := filepath.Join(tempDir, filepath.Base(target))
	if err := copyFile(absolute, destination); err != nil {
		_ = os.RemoveAll(tempDir)
		return "", "", "", err
	}
	return tempDir, "file", tempDir, nil
}

func looksLikeGitURL(parsed *url.URL) bool {
	path := strings.ToLower(parsed.Path)
	if strings.Contains(path, "/raw/") || strings.Contains(path, "/blob/") {
		return false
	}
	for _, suffix := range []string{".md", ".py", ".sh", ".zip"} {
		if strings.HasSuffix(path, suffix) {
			return false
		}
	}
	return allowedGitHosts[strings.ToLower(parsed.Hostname())] || strings.HasSuffix(path, ".git")
}

func validateRemoteHost(ctx context.Context, host string, allow map[string]bool) error {
	allowed := allow[host]
	if !allowed {
		for candidate := range allow {
			if strings.HasSuffix(host, "."+candidate) {
				allowed = true
				break
			}
		}
	}
	if !allowed {
		return fmt.Errorf("host %q is not allowed", host)
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		return fmt.Errorf("could not safely resolve host %q", host)
	}
	for _, address := range addresses {
		ip := address.IP
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("host %q resolves to a private or reserved address", host)
		}
	}
	return nil
}

func download(ctx context.Context, target string) (string, string, string, error) {
	client := &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", "", "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", "", "", fmt.Errorf("download target: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", "", "", fmt.Errorf("download target returned HTTP %d", response.StatusCode)
	}
	if response.ContentLength > maxDownloadBytes {
		return "", "", "", fmt.Errorf("download exceeds %d bytes", maxDownloadBytes)
	}
	tempDir, err := makeTempDir()
	if err != nil {
		return "", "", "", err
	}
	name := filepath.Base(request.URL.Path)
	if name == "." || name == "/" || name == "" {
		name = "SKILL.md"
	}
	destination := filepath.Join(tempDir, name)
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return "", "", "", err
	}
	written, copyErr := io.Copy(file, io.LimitReader(response.Body, maxDownloadBytes+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.RemoveAll(tempDir)
		return "", "", "", errors.Join(copyErr, closeErr)
	}
	if written > maxDownloadBytes {
		_ = os.RemoveAll(tempDir)
		return "", "", "", fmt.Errorf("download exceeds %d bytes", maxDownloadBytes)
	}
	if strings.EqualFold(filepath.Ext(name), ".zip") || strings.Contains(response.Header.Get("Content-Type"), "zip") {
		return extractZip(destination, tempDir)
	}
	return tempDir, "url", tempDir, nil
}

func extractZip(path, existingTemp string) (resolvedRoot, sourceType, cleanupDir string, returnErr error) {
	tempDir := existingTemp
	defer func() {
		if returnErr != nil && tempDir != "" {
			_ = os.RemoveAll(tempDir)
		}
	}()
	var err error
	if tempDir == "" {
		tempDir, err = makeTempDir()
		if err != nil {
			return "", "", "", err
		}
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return "", "", "", fmt.Errorf("invalid zip file: %w", err)
	}
	defer reader.Close()
	if len(reader.File) > maxArchiveMembers {
		_ = os.RemoveAll(tempDir)
		return "", "", "", fmt.Errorf("zip contains more than %d entries", maxArchiveMembers)
	}
	extractRoot := filepath.Join(tempDir, "extracted")
	if err := os.MkdirAll(extractRoot, 0o700); err != nil {
		return "", "", "", err
	}
	cleanRoot := filepath.Clean(extractRoot) + string(os.PathSeparator)
	var expanded uint64
	for _, member := range reader.File {
		expanded += member.UncompressedSize64
		if expanded > maxArchiveBytes {
			_ = os.RemoveAll(tempDir)
			return "", "", "", fmt.Errorf("zip expands beyond %d bytes", maxArchiveBytes)
		}
		destination := filepath.Clean(filepath.Join(extractRoot, member.Name))
		if !strings.HasPrefix(destination, cleanRoot) {
			return "", "", "", fmt.Errorf("zip entry %q escapes extraction directory", member.Name)
		}
		if member.FileInfo().Mode()&os.ModeSymlink != 0 {
			return "", "", "", fmt.Errorf("zip entry %q is a symbolic link", member.Name)
		}
		if member.FileInfo().IsDir() {
			if err := os.MkdirAll(destination, 0o700); err != nil {
				return "", "", "", err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return "", "", "", err
		}
		source, err := member.Open()
		if err != nil {
			return "", "", "", err
		}
		dest, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err != nil {
			source.Close()
			return "", "", "", err
		}
		written, copyErr := io.Copy(dest, io.LimitReader(source, maxArchiveBytes+1))
		closeErr := errors.Join(source.Close(), dest.Close())
		if copyErr != nil || closeErr != nil {
			return "", "", "", errors.Join(copyErr, closeErr)
		}
		if written > maxArchiveBytes {
			return "", "", "", fmt.Errorf("zip entry %q exceeds extraction limit", member.Name)
		}
	}
	return extractRoot, "zip", tempDir, nil
}

func makeTempDir() (string, error) {
	root := strings.TrimSpace(os.Getenv("SCAN_KERNEL_WORK_DIR"))
	if root != "" {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return "", err
		}
	}
	return os.MkdirTemp(root, "scan_kernel_")
}

func copyFile(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	return errors.Join(copyErr, output.Close())
}

func readComponents(root string) ([]component, map[string]any, error) {
	allowed := map[string]string{
		".py": "python", ".sh": "shell", ".bash": "shell", ".zsh": "shell",
		".md": "markdown", ".markdown": "markdown", ".json": "json",
		".yaml": "yaml", ".yml": "yaml", ".toml": "toml", ".js": "javascript",
		".ts": "typescript", ".txt": "text", ".rb": "ruby", ".go": "go", ".rs": "rust",
	}
	var components []component
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "__pycache__", "node_modules", ".venv", "venv", ".tox", ".pytest_cache":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(entry.Name(), ".") && !strings.HasPrefix(entry.Name(), ".claude") {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		kind := allowed[ext]
		if kind == "" {
			kind = "other"
		}
		info, err := entry.Info()
		if entry.Type()&os.ModeSymlink != 0 {
			resolved, resolveErr := filepath.EvalSymlinks(path)
			if resolveErr != nil {
				return nil
			}
			relativeTarget, relativeErr := filepath.Rel(root, resolved)
			if relativeErr != nil || relativeTarget == ".." || strings.HasPrefix(relativeTarget, ".."+string(os.PathSeparator)) {
				return nil
			}
			info, err = os.Stat(resolved)
			if err == nil && info.IsDir() {
				return nil
			}
		}
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		content := pythonDecodeUTF8(raw)
		// Normalize newlines before offsets, line numbers, or analyzer matches
		// are computed so mixed CRLF/CR inputs have stable scanner semantics.
		content = strings.ReplaceAll(strings.ReplaceAll(content, "\r\n", "\n"), "\r", "\n")
		components = append(components, component{
			Path: filepath.ToSlash(relative), Type: kind, Lines: pythonLineCount(content),
			Executable: ext == ".py" || ext == ".sh" || ext == ".bash" || ext == ".zsh" ||
				ext == ".js" || ext == ".ts" || ext == ".rb" || ext == ".go" || ext == ".rs" || ext == ".pl",
			SizeBytes: len(raw), Content: content,
		})
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(components, func(i, j int) bool { return components[i].Path < components[j].Path })
	manifest := map[string]any{}
	for _, manifestName := range []string{"SKILL.md", "skill.md"} {
		for _, item := range components {
			if item.Path == manifestName {
				manifest = parseFrontmatter(item.Content)
				return components, manifest, nil
			}
		}
	}
	return components, manifest, nil
}

// pythonDecodeUTF8 mirrors bytes.decode("utf-8", errors="replace"). Unlike
// strings.ToValidUTF8, Python does not collapse an arbitrary run of malformed
// bytes into one replacement character; it consumes the valid prefix of a
// malformed sequence and emits one replacement for that sequence.
func pythonDecodeUTF8(raw []byte) string {
	var decoded strings.Builder
	decoded.Grow(len(raw))
	for index := 0; index < len(raw); {
		first := raw[index]
		if first < 0x80 {
			decoded.WriteByte(first)
			index++
			continue
		}
		width := 0
		secondMin, secondMax := byte(0x80), byte(0xBF)
		switch {
		case first >= 0xC2 && first <= 0xDF:
			width = 2
		case first >= 0xE0 && first <= 0xEF:
			width = 3
			if first == 0xE0 {
				secondMin = 0xA0
			} else if first == 0xED {
				secondMax = 0x9F
			}
		case first >= 0xF0 && first <= 0xF4:
			width = 4
			if first == 0xF0 {
				secondMin = 0x90
			} else if first == 0xF4 {
				secondMax = 0x8F
			}
		default:
			decoded.WriteRune('�')
			index++
			continue
		}

		consumed := 1
		if index+1 < len(raw) && raw[index+1] >= secondMin && raw[index+1] <= secondMax {
			consumed = 2
			for consumed < width && index+consumed < len(raw) && raw[index+consumed] >= 0x80 && raw[index+consumed] <= 0xBF {
				consumed++
			}
		}
		if consumed == width {
			decoded.Write(raw[index : index+width])
			index += width
			continue
		}
		decoded.WriteRune('�')
		index += consumed
	}
	return decoded.String()
}

func parseFrontmatter(content string) map[string]any {
	if !strings.HasPrefix(content, "---") {
		return map[string]any{}
	}
	endPattern := regexp.MustCompile(`\n---\s*\n`)
	end := endPattern.FindStringIndex(content[3:])
	if len(end) != 2 {
		return map[string]any{}
	}
	var decoded map[string]any
	if err := yamlUnmarshal([]byte(content[3:3+end[0]]), &decoded); err != nil {
		return map[string]any{}
	}
	if decoded == nil {
		return map[string]any{}
	}
	manifest := map[string]any{}
	if value, exists := decoded["name"]; exists {
		manifest["name"] = value
	}
	if value, exists := decoded["description"]; exists {
		manifest["description"] = value
	}
	manifest["triggers"] = manifestStringList(decoded["triggers"])
	manifest["permissions"] = manifestStringList(decoded["permissions"])
	allowedTools := manifestStringList(decoded["allowed-tools"])
	if text, ok := decoded["allowed-tools"].(string); ok {
		allowedTools = nil
		for _, value := range strings.Split(text, ",") {
			if value = strings.TrimSpace(value); value != "" {
				allowedTools = append(allowedTools, value)
			}
		}
	}
	manifest["allowed-tools"] = allowedTools
	parameters := make([]any, 0)
	if raw, ok := decoded["parameters"].([]any); ok {
		for _, value := range raw {
			if _, ok := value.(map[string]any); ok {
				parameters = append(parameters, value)
			}
		}
	}
	manifest["parameters"] = parameters
	return manifest
}

func manifestStringList(value any) []any {
	raw, ok := value.([]any)
	if !ok {
		return []any{}
	}
	result := make([]any, 0, len(raw))
	for _, item := range raw {
		text := strings.TrimSpace(fmt.Sprint(item))
		if text != "" {
			result = append(result, text)
		}
	}
	return result
}

func pythonLineCount(content string) int {
	if content == "" {
		return 0
	}
	count := 0
	endedWithBoundary := false
	previousCR := false
	for _, character := range content {
		if previousCR {
			previousCR = false
			if character == '\n' {
				continue
			}
		}
		switch character {
		case '\r':
			count++
			endedWithBoundary = true
			previousCR = true
		case '\n', '\v', '\f', '\x1c', '\x1d', '\x1e', '\u0085', '\u2028', '\u2029':
			count++
			endedWithBoundary = true
		default:
			endedWithBoundary = false
		}
	}
	if !endedWithBoundary {
		count++
	}
	return count
}
