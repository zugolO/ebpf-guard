// Package store provides AES-256-GCM column-level encryption helpers for the
// SQLite alert store. These functions are pure-Go (no CGO) and are used by the
// CGO-gated sqlite.go implementation.
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// loadEncryptionKey reads a 32-byte AES-256 key from the configured source.
// keyEnv takes precedence over keyFile when both are set.
// The key must be a 64-character hex string or a base64-encoded string that
// decodes to exactly 32 bytes.
func loadEncryptionKey(keyEnv, keyFile string) ([]byte, error) {
	var raw string
	switch {
	case keyEnv != "":
		raw = strings.TrimSpace(os.Getenv(keyEnv))
		if raw == "" {
			return nil, fmt.Errorf("store: encryption key env var %q is unset or empty", keyEnv)
		}
	case keyFile != "":
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("store: read encryption key file %q: %w", keyFile, err)
		}
		raw = strings.TrimSpace(string(data))
	default:
		return nil, fmt.Errorf("store: encryption enabled but neither key_env nor key_file is set")
	}
	return decodeKey(raw)
}

// decodeKey accepts a 64-char hex string or a base64 string and returns the
// decoded 32-byte AES-256 key. Returns an error if the value is not 32 bytes.
func decodeKey(raw string) ([]byte, error) {
	// Try 64-character hex (32 bytes)
	if len(raw) == 64 {
		key, err := hex.DecodeString(raw)
		if err == nil && len(key) == 32 {
			return key, nil
		}
	}
	// Try standard base64 (44 chars with padding) and raw base64 (43 chars)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		key, err := enc.DecodeString(raw)
		if err == nil && len(key) == 32 {
			return key, nil
		}
	}
	return nil, fmt.Errorf("store: encryption key must decode to exactly 32 bytes (64-char hex or 44-char base64)")
}

// encryptColumn encrypts plaintext using AES-256-GCM and returns a base64-
// encoded blob of the form base64(nonce || ciphertext || GCM-tag).
// A fresh 12-byte random nonce is generated for every call so each row gets a
// unique ciphertext even when the plaintext is identical.
func encryptColumn(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("store: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("store: new gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("store: generate nonce: %w", err)
	}
	// Seal appends (ciphertext || tag) to nonce, producing nonce||ciphertext||tag
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// decryptColumn decrypts an AES-256-GCM ciphertext produced by encryptColumn.
// Returns an error if authentication fails, the key is wrong, the data is
// truncated, or it is not valid base64.
func decryptColumn(key []byte, encoded string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("store: base64 decode: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("store: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("store: new gcm: %w", err)
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("store: ciphertext too short (%d bytes)", len(data))
	}
	plain, err := gcm.Open(nil, data[:ns], data[ns:], nil)
	if err != nil {
		return nil, fmt.Errorf("store: gcm authentication failed: %w", err)
	}
	if plain == nil {
		plain = []byte{}
	}
	return plain, nil
}
