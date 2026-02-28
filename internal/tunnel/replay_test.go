package tunnel

import (
	"testing"
	"time"
)

func TestHandshakeReplayProtector_DedupWithinTTL(t *testing.T) {
	t.Parallel()

	var nonce [kipHelloNonceSize]byte
	for i := 0; i < len(nonce); i++ {
		nonce[i] = byte(i)
	}

	p := &handshakeReplayProtector{}
	now := time.Unix(1_700_000_000, 0)

	if !p.allow("userA", nonce, now) {
		t.Fatalf("first allow must succeed")
	}
	if p.allow("userA", nonce, now.Add(1*time.Second)) {
		t.Fatalf("duplicate nonce within TTL must be rejected")
	}
	if !p.allow("userB", nonce, now.Add(1*time.Second)) {
		t.Fatalf("same nonce for different user must be allowed")
	}

	ttl := handshakeReplayTTL
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	if !p.allow("userA", nonce, now.Add(ttl+1*time.Second)) {
		t.Fatalf("nonce should be allowed after TTL")
	}
}

func TestHandshakeReplayProtector_EmptyUserHashUsesSharedBucket(t *testing.T) {
	t.Parallel()

	var nonce [kipHelloNonceSize]byte
	nonce[0] = 0x42

	p := &handshakeReplayProtector{}
	now := time.Unix(1_700_000_000, 0)

	if !p.allow("", nonce, now) {
		t.Fatalf("first allow must succeed")
	}
	if p.allow("", nonce, now.Add(1*time.Second)) {
		t.Fatalf("duplicate nonce with empty userHash must be rejected")
	}
}
