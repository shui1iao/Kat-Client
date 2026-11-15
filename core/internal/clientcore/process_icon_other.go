//go:build !windows

package clientcore

func extractProcessIconDataURI(_ string) string {
	return ""
}
