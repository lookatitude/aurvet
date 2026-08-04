// internal/alpm/desc.go
package alpm

import (
	"bufio"
	"io"
	"strings"
)

// ParseDesc reads the pacman local-DB `desc` format: a %KEY% line followed by
// one or more value lines, terminated by a blank line. Unknown and absent keys
// are not errors — measured on the reference system, several packages omit
// %SIZE%, %XDATA% or %LICENSE%.
func ParseDesc(r io.Reader) (map[string][]string, error) {
	out := make(map[string][]string)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	key := ""
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			key = ""
		case strings.HasPrefix(line, "%") && strings.HasSuffix(line, "%") && len(line) > 2:
			key = line[1 : len(line)-1]
			if _, ok := out[key]; !ok {
				out[key] = nil
			}
		case key != "":
			out[key] = append(out[key], line)
		}
	}
	return out, sc.Err()
}
