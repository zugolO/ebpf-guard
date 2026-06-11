package store

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testKey returns a deterministic 32-byte AES-256 key for testing.
func testKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

func TestEncryptDecryptColumn_Roundtrip(t *testing.T) {
	key := testKey()
	cases := [][]byte{
		[]byte("sensitive alert message with PII"),
		[]byte(`{"pid":1234,"comm":"bash","args":["--login"]}`),
		[]byte(""),
		[]byte("short"),
	}
	for _, plaintext := range cases {
		enc, err := encryptColumn(key, plaintext)
		require.NoError(t, err, "encrypt must succeed")

		got, err := decryptColumn(key, enc)
		require.NoError(t, err, "decrypt with correct key must succeed")
		assert.Equal(t, plaintext, got, "roundtrip must recover original plaintext")
	}
}

func TestEncryptColumn_UniqueCiphertexts(t *testing.T) {
	key := testKey()
	plain := []byte("same plaintext")

	enc1, err := encryptColumn(key, plain)
	require.NoError(t, err)
	enc2, err := encryptColumn(key, plain)
	require.NoError(t, err)

	// Each call generates a fresh nonce so ciphertexts must differ.
	assert.NotEqual(t, enc1, enc2, "two encryptions of identical plaintext must produce different ciphertexts")
}

func TestDecryptColumn_WrongKeyFails(t *testing.T) {
	key := testKey()
	plain := []byte("secret data")
	enc, err := encryptColumn(key, plain)
	require.NoError(t, err)

	wrongKey := make([]byte, 32) // all zeros
	_, err = decryptColumn(wrongKey, enc)
	assert.Error(t, err, "decryption with wrong key must fail")
}

func TestDecryptColumn_TamperedCiphertextFails(t *testing.T) {
	key := testKey()
	enc, err := encryptColumn(key, []byte("data"))
	require.NoError(t, err)

	// Flip a byte in the decoded payload
	raw, _ := base64.StdEncoding.DecodeString(enc)
	raw[len(raw)-1] ^= 0xFF
	tampered := base64.StdEncoding.EncodeToString(raw)

	_, err = decryptColumn(key, tampered)
	assert.Error(t, err, "decryption of tampered ciphertext must fail")
}

func TestDecryptColumn_PlaintextInput(t *testing.T) {
	// When decryption is enabled but a row was written in plaintext (migration),
	// decryptColumn should return an error so the caller can fall back gracefully.
	key := testKey()
	_, err := decryptColumn(key, `{"rule_id":"test","severity":"warning"}`)
	assert.Error(t, err, "decryptColumn must return an error on non-encrypted input")
}

func TestDecodeKey_Hex(t *testing.T) {
	key := testKey()
	hexStr := hex.EncodeToString(key)
	decoded, err := decodeKey(hexStr)
	require.NoError(t, err)
	assert.Equal(t, key, decoded)
}

func TestDecodeKey_Base64(t *testing.T) {
	key := testKey()
	b64Str := base64.StdEncoding.EncodeToString(key)
	decoded, err := decodeKey(b64Str)
	require.NoError(t, err)
	assert.Equal(t, key, decoded)
}

func TestDecodeKey_Invalid(t *testing.T) {
	cases := []string{
		"short",
		"not-valid-hex-or-base64!!",
		hex.EncodeToString(make([]byte, 16)), // 32 hex chars = 16 bytes, not 32
	}
	for _, tc := range cases {
		_, err := decodeKey(tc)
		assert.Error(t, err, "decodeKey(%q) must fail", tc)
	}
}

func TestLoadEncryptionKey_FromEnv(t *testing.T) {
	key := testKey()
	envVar := "TEST_EBPF_GUARD_ENC_KEY"
	t.Setenv(envVar, hex.EncodeToString(key))

	loaded, err := loadEncryptionKey(envVar, "")
	require.NoError(t, err)
	assert.Equal(t, key, loaded)
}

func TestLoadEncryptionKey_FromFile(t *testing.T) {
	key := testKey()
	f, err := os.CreateTemp(t.TempDir(), "enc-key-*")
	require.NoError(t, err)
	_, err = f.WriteString(hex.EncodeToString(key))
	require.NoError(t, err)
	f.Close()

	loaded, err := loadEncryptionKey("", f.Name())
	require.NoError(t, err)
	assert.Equal(t, key, loaded)
}

func TestLoadEncryptionKey_NeitherSet(t *testing.T) {
	_, err := loadEncryptionKey("", "")
	assert.Error(t, err)
}

func TestLoadEncryptionKey_EmptyEnvVar(t *testing.T) {
	envVar := "TEST_EBPF_GUARD_EMPTY_KEY"
	t.Setenv(envVar, "")
	_, err := loadEncryptionKey(envVar, "")
	assert.Error(t, err)
}

func TestEncryptedDataNotReadableWithoutKey(t *testing.T) {
	key := testKey()
	sensitiveData := []byte("process args: --password=s3cr3t --token=ghp_xxx")

	enc, err := encryptColumn(key, sensitiveData)
	require.NoError(t, err)

	// The base64-encoded ciphertext must not contain the plaintext verbatim.
	assert.False(t, bytes.Contains([]byte(enc), sensitiveData),
		"ciphertext must not contain plaintext")

	// Decoding the base64 ciphertext raw must not contain plaintext.
	raw, _ := base64.StdEncoding.DecodeString(enc)
	assert.False(t, bytes.Contains(raw, sensitiveData),
		"raw ciphertext bytes must not contain plaintext")
}
