//go:build !yara_native

package buildinfo

func yaraDetails() (string, string, []string) {
	return "fallback", "", []string{}
}
