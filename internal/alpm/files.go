// internal/alpm/files.go
package alpm

import (
	"bufio"
	"io"
	"strings"
)

// ParseFiles reads the local-DB `files` format. Two sections matter: %FILES%
// lists owned paths (the ownership oracle), and %BACKUP% lists config files
// pacman expects to change, as path<TAB>md5. The digest is MD5, not SHA256 —
// verified against the reference system.
func ParseFiles(r io.Reader) ([]string, map[string]string, error) {
	var paths []string
	backup := make(map[string]string)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	section := ""
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "%") && strings.HasSuffix(line, "%") && len(line) > 2:
			section = line[1 : len(line)-1]
		case section == "FILES":
			paths = append(paths, line)
		case section == "BACKUP":
			path, digest, found := strings.Cut(line, "\t")
			if found {
				backup[path] = digest
			}
		}
	}
	return paths, backup, sc.Err()
}
