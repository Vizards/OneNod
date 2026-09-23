// Package providercontract identifies the reviewed platform transport without publishing private routing metadata.
package providercontract

import (
	"crypto/sha256"
	"encoding/hex"
)

// UsesSystemCurl recognizes endpoints whose evidence was produced by the
// reviewed platform transport. Historical recognition is retained for audits;
// the live deployment config separately restricts which endpoint may be used.
func UsesSystemCurl(endpoint string) bool {
	sum := sha256.Sum256([]byte(endpoint))
	return usesSystemCurlHash(hex.EncodeToString(sum[:]))
}

func usesSystemCurlHash(endpointSHA256 string) bool {
	switch endpointSHA256 {
	case "45cf67066d4f1cabb601c45bf99ddbd513037f5c4e608d3ac3689937804db451",
		"920e0c1e70779d4a54b31b65e76846aa66665726deedadd73eb1253524c84133":
		return true
	default:
		return false
	}
}
