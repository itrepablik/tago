package tago

import (
	"testing"
)

func TestEncrypt(t *testing.T) {
	// Generate a secure random IV
	iv, err := GenerateIV()
	if err != nil {
		t.Fatalf("error generating IV: %s", err)
	}

	// Generate a secure random salt
	secretKey, err := GenerateSecretKey(32)
	if err != nil {
		t.Fatalf("error generating secret key: %s", err)
	}

	// Encrypt a string
	plaintext := "Hello World!"
	ciphertext, err := Encrypt(plaintext, string(secretKey), iv)
	if err != nil {
		t.Fatalf("error encrypting string: %s", err)
	}
	if ciphertext == plaintext {
		t.Fatalf("plaintext and ciphertext should not be the same")
	}

	t.Logf("plaintext: %s\nciphertext: %s", plaintext, ciphertext)
}

func TestDecrypt(t *testing.T) {
	// Generate a secure random IV
	iv, err := GenerateIV()
	if err != nil {
		t.Fatalf("error generating IV: %s", err)
	}

	// Generate a secure random salt
	secretKey, err := GenerateSecretKey(32)
	if err != nil {
		t.Fatalf("error generating secret key: %s", err)
	}

	// Encrypt a string
	plaintext := "Hello World!"
	ciphertext, err := Encrypt(plaintext, string(secretKey), iv)
	if err != nil {
		t.Fatalf("error encrypting string: %s", err)
	}
	if ciphertext == plaintext {
		t.Fatalf("plaintext and ciphertext should not be the same")
	}

	// Test to Decrypt back to original plaintext
	decrypted, err := Decrypt(ciphertext, string(secretKey), iv)
	if err != nil {
		t.Fatalf("error decrypting string: %s", err)
	}
	if decrypted != plaintext {
		t.Fatalf("decrypted string should be the same as plaintext")
	}
	t.Logf("plaintext: %s\nciphertext: %s\ndecrypted: %s", plaintext, ciphertext, decrypted)
}

func TestGenerateSecretKey(t *testing.T) {
	// Generate a secure random salt
	secretKey, err := GenerateSecretKey(32)
	if err != nil {
		t.Fatalf("error generating secret key: %s", err)
	}
	if len(secretKey) != 32 {
		t.Fatalf("secret key length should be 32, got %d", len(secretKey))
	}
	t.Logf("secret key: %s", secretKey)
}

func TestGenerateIV(t *testing.T) {
	// Generate a secure random IV
	iv, err := GenerateIV()
	if err != nil {
		t.Fatalf("error generating IV: %s", err)
	}
	if len(iv) != 16 {
		t.Fatalf("IV length should be 16, got %d", len(iv))
	}
	t.Logf("IV: %s", string(iv))
}
