package utils

import "encoding/base64"

func EncodeToBase64URL(data []byte) string {
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(data)
}
