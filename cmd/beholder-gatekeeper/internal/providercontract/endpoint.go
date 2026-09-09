// Package providercontract identifies the reviewed platform transport without publishing private routing metadata.
package providercontract

import (
	"crypto/sha256"
	"encoding/hex"
)

// UsesSystemCurl keeps the previously confirmed endpoint selection exact.
func UsesSystemCurl(endpoint string) bool {
	sum := sha256.Sum256([]byte(endpoint))
	return hex.EncodeToString(sum[:]) == "920e0c1e70779d4a54b31b65e76846aa66665726deedadd73eb1253524c84133"
}
