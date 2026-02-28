package apis

import (
	"crypto/sha256"
	"testing"
)

func TestKIPUserHashFromKey(t *testing.T) {
	key := "handshake-key"
	got := kipUserHashFromKey(key)
	want := sha256.Sum256([]byte(key))
	for i := 0; i < 8; i++ {
		if got[i] != want[i] {
			t.Fatalf("mismatch at %d", i)
		}
	}
}
