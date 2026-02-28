package tunnel

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/saba-futai/sudoku/internal/config"
	"github.com/saba-futai/sudoku/pkg/crypto"
	"github.com/saba-futai/sudoku/pkg/obfs/sudoku"
)

const (
	kipHandshakeSkew = 60 * time.Second
)

func KIPHandshakeClient(rc *crypto.RecordConn, seed string, userHash [kipHelloUserHashSize]byte, feats uint32) (selectedFeats uint32, err error) {
	if rc == nil {
		return 0, fmt.Errorf("nil conn")
	}

	curve := ecdh.X25519()
	ephemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return 0, fmt.Errorf("ecdh generate failed: %w", err)
	}

	var nonce [kipHelloNonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return 0, fmt.Errorf("nonce generate failed: %w", err)
	}

	var clientPub [kipHelloPubSize]byte
	copy(clientPub[:], ephemeral.PublicKey().Bytes())

	ch := &KIPClientHello{
		Timestamp: time.Now(),
		UserHash:  userHash,
		Nonce:     nonce,
		ClientPub: clientPub,
		Features:  feats,
	}
	if err := WriteKIPMessage(rc, KIPTypeClientHello, ch.EncodePayload()); err != nil {
		return 0, fmt.Errorf("write client hello failed: %w", err)
	}

	msg, err := ReadKIPMessage(rc)
	if err != nil {
		return 0, fmt.Errorf("read server hello failed: %w", err)
	}
	if msg.Type != KIPTypeServerHello {
		return 0, fmt.Errorf("unexpected handshake message: %d", msg.Type)
	}
	sh, err := DecodeKIPServerHelloPayload(msg.Payload)
	if err != nil {
		return 0, fmt.Errorf("decode server hello failed: %w", err)
	}
	if sh.Nonce != nonce {
		return 0, fmt.Errorf("handshake nonce mismatch")
	}

	shared, err := x25519SharedSecret(ephemeral, sh.ServerPub[:])
	if err != nil {
		return 0, fmt.Errorf("ecdh failed: %w", err)
	}
	sessC2S, sessS2C, err := deriveSessionDirectionalBases(seed, shared, nonce)
	if err != nil {
		return 0, fmt.Errorf("derive session keys failed: %w", err)
	}
	if err := rc.Rekey(sessC2S, sessS2C); err != nil {
		return 0, fmt.Errorf("rekey failed: %w", err)
	}

	return sh.SelectedFeats, nil
}

func ClientHandshake(conn net.Conn, cfg *config.Config, table *sudoku.Table, privateKey []byte) (net.Conn, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config")
	}
	if table == nil {
		return nil, fmt.Errorf("nil table")
	}
	if !cfg.EnablePureDownlink && cfg.AEAD == "none" {
		return nil, fmt.Errorf("enable_pure_downlink=false requires AEAD")
	}

	obfsConn := buildObfsConnForClient(conn, table, cfg)

	pskC2S, pskS2C := derivePSKDirectionalBases(cfg.Key)
	rc, err := crypto.NewRecordConn(obfsConn, cfg.AEAD, pskC2S, pskS2C)
	if err != nil {
		return nil, fmt.Errorf("crypto setup failed: %w", err)
	}

	userHash := kipUserHashFromPrivateKey(privateKey, cfg.Key)
	if _, err := KIPHandshakeClient(rc, cfg.Key, userHash, KIPFeatAll); err != nil {
		_ = rc.Close()
		return nil, err
	}
	return rc, nil
}
