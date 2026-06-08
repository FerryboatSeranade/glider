package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	settingsKeyEnv      = "GLIDER_SETTINGS_KEY"
	encryptedSecretV1   = "enc:v1:"
	settingsKeyMinBytes = 16
)

func encodeStoredSecret(secret string) (string, error) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return "", nil
	}
	key := strings.TrimSpace(os.Getenv(settingsKeyEnv))
	if key == "" {
		return secret, nil
	}
	gcm, err := settingsGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(secret), nil)
	raw := append(nonce, ciphertext...)
	return encryptedSecretV1 + base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeStoredSecret(stored string) (string, error) {
	stored = strings.TrimSpace(stored)
	if stored == "" {
		return "", nil
	}
	if !strings.HasPrefix(stored, encryptedSecretV1) {
		return stored, nil
	}
	key := strings.TrimSpace(os.Getenv(settingsKeyEnv))
	if key == "" {
		return "", fmt.Errorf("%s is required to decrypt stored settings", settingsKeyEnv)
	}
	gcm, err := settingsGCM(key)
	if err != nil {
		return "", err
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(stored, encryptedSecretV1))
	if err != nil {
		return "", err
	}
	if len(raw) <= gcm.NonceSize() {
		return "", fmt.Errorf("encrypted setting is invalid")
	}
	nonce := raw[:gcm.NonceSize()]
	ciphertext := raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func settingsGCM(key string) (cipher.AEAD, error) {
	if len(key) < settingsKeyMinBytes {
		return nil, fmt.Errorf("%s must be at least %d bytes", settingsKeyEnv, settingsKeyMinBytes)
	}
	sum := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
