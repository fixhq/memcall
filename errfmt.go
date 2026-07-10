//go:build !debug

package memcall

// _addr returns a redaction placeholder in production builds so the address of
// a protected buffer never leaks into error strings (and from there into logs).
// Build with the `debug` tag to include the real address instead.
func _addr(_ []byte) string {
	return "(redacted)"
}
