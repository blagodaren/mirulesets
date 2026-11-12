package rules

import (
	"github.com/klauspost/compress/zstd"
	"testing"
)

func FuzzMRSDecoder(f *testing.F) {
	for _, behavior := range []string{"domain", "ipcidr"} {
		lines := []string{"+.example.com", "*.example.org"}
		if behavior == "ipcidr" {
			lines = []string{"192.0.2.0/24", "2001:db8::/32"}
		}
		data, err := Encode(lines, "mrs", behavior)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data, behavior == "ipcidr")
	}
	f.Add([]byte("invalid"), false)
	f.Add([]byte{}, true)
	f.Fuzz(func(t *testing.T, data []byte, ip bool) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		behavior := "domain"
		if ip {
			behavior = "ipcidr"
		}
		_, _ = Parse(data, "mrs", behavior)
	})
}

// Mutating the decompressed body exercises lengths and trie structure directly;
// most mutations of compressed bytes otherwise stop at the zstd checksum.
func FuzzMRSPayload(f *testing.F) {
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		f.Fatal(err)
	}
	for _, behavior := range []string{"domain", "ipcidr"} {
		lines := []string{"+.example.com", "*.example.org"}
		if behavior == "ipcidr" {
			lines = []string{"192.0.2.0/24", "2001:db8::/32"}
		}
		data, err := Encode(lines, "mrs", behavior)
		if err != nil {
			f.Fatal(err)
		}
		raw, err := decoder.DecodeAll(data, nil)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw, behavior == "ipcidr")
	}
	decoder.Close()
	f.Fuzz(func(t *testing.T, data []byte, ip bool) {
		if len(data) > 4096 {
			t.Skip()
		}
		encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
		if err != nil {
			t.Fatal(err)
		}
		compressed := encoder.EncodeAll(data, nil)
		encoder.Close()
		behavior := "domain"
		if ip {
			behavior = "ipcidr"
		}
		_, _ = Parse(compressed, "mrs", behavior)
	})
}
