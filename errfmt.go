//go:build !memcall_debug

package memcall

// _addr returns a redaction placeholder in production builds so the address of
// a protected buffer never leaks into error strings (and from there into logs).
// Build with the `memcall_debug` tag to include the real address instead. The
// tag is namespaced so a downstream `-tags debug` cannot flip it accidentally.
func _addr(_ []byte) string {
	return "(redacted)"
}
