// Package providercontract identifies the reviewed platform transport without publishing private routing metadata.
package providercontract

import (
	"crypto/sha256"
	"encoding/hex"
)

// UsesSystemCurl keeps the confirmed direct-provider endpoint selection exact.
func UsesSystemCurl(endpoint string) bool {
	sum := sha256.Sum256([]byte(endpoint))
	return hex.EncodeToString(sum[:]) == "45cf67066d4f1cabb601c45bf99ddbd513037f5c4e608d3ac3689937804db451"
}
