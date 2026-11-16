package rmqtest

import (
	"bytes"
	"compress/zlib"
)

// Deflate compresses as a producer that compresses does: zlib.
func Deflate(b []byte) []byte {
	var out bytes.Buffer
	w := zlib.NewWriter(&out)
	w.Write(b)
	w.Close()
	return out.Bytes()
}
