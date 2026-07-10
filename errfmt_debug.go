//go:build debug

package memcall

import "fmt"

// _addr returns the start address of the buffer for inclusion in error
// messages. Only compiled into `debug` builds; production builds redact it
// (see errfmt.go).
func _addr(b []byte) string {
	return fmt.Sprintf("%p", _getStartPtr(b))
}
