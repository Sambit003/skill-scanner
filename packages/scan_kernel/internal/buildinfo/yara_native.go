//go:build yara_native

package buildinfo

func yaraDetails() (string, string, []string) {
	return "native-static", "4.5.4", []string{
		"tests", "pe", "elf", "math", "time", "console", "string", "dotnet", "hash",
	}
}
