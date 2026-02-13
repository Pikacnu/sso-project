package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"time"

	"sso-server/ent/generated/openidkey"
	ent "sso-server/src/db"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
)

var CurrentKeyPair *KeyPair

func InitKey() {
	ctxBg := context.Background()
	queryKeyPair, err := ent.Client.OpenIDKey.Query().
		Where(openidkey.IsActiveEQ(true)).
		Order(openidkey.ByCreatedAt(sql.OrderDesc())).Only(ctxBg)
	if err == nil && queryKeyPair != nil {
		// Try to load private key PEM first
		if queryKeyPair.PrivateKey != "" {
			block, _ := pem.Decode([]byte(queryKeyPair.PrivateKey))
			if block != nil {
				if priv, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
					CurrentKeyPair = &KeyPair{
						PrivateKey: priv,
						PublicKey:  &priv.PublicKey,
						Modulus:    queryKeyPair.Modulus,
						Exponent:   queryKeyPair.Exponent,
					}
					return
				}
			}
		}
	}

	// No key found or failed to parse: generate and persist a new keypair
	kp, err := GenerateKeys()
	if err != nil {
		panic(err)
	}
	CurrentKeyPair = kp
}

func isFileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

type KeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Modulus    string
	Exponent   string
	Kid        string
}

func GenerateKeys() (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	publicKey := &privateKey.PublicKey
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Generate a unique Key ID (kid) for this key pair
	kidUUID, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	kidStr := kidUUID.String()

	keyPair := &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Modulus:    encodeToBase64URL(publicKey.N.Bytes()),
		Exponent:   encodeToBase64URL(big.NewInt(int64(publicKey.E)).Bytes()),
		Kid:        kidStr,
	}

	// Also persist public key PEM and metadata into database (OpenIDKey table)
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	// Persist using Ent
	ctx := context.Background()
	if _, err := ent.Client.OpenIDKey.Create().
		SetKid(kidStr).
		SetPrivateKey(string(privateKeyPEM)).
		SetPublicKey(string(publicKeyPEM)).
		SetModulus(keyPair.Modulus).
		SetExponent(keyPair.Exponent).
		SetIsActive(true).
		Save(ctx); err != nil {
		return nil, err
	}

	// set in-memory current key pair
	CurrentKeyPair = keyPair

	return keyPair, nil
}

func encodeToBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeBase64URL(s string) []byte {
	data, _ := base64.RawURLEncoding.DecodeString(s)
	return data
}

func cleanupOldKeys() {
	expireDays := cfg.OpenIDKeyExpireDays
	ctxBg := context.Background()
	cutoffTime := time.Now().AddDate(0, 0, -expireDays)
	_, err := ent.Client.OpenIDKey.Delete().Where(openidkey.CreatedAtLT(cutoffTime)).Exec(ctxBg)
	if err != nil {
		// Log error but don't panic
	}
}

type JWK struct {
	Kid string `json:"kid"` // Key ID
	Kty string `json:"kty"` // Key Type (e.g., RSA)
	Use string `json:"use"` // Public Key Use (e.g., sig for signature)
	Alg string `json:"alg"` // Algorithm (e.g., RS256)
	N   string `json:"n"`   // Modulus for RSA
	E   string `json:"e"`   // Exponent for RSA
}

func GetAvailableKeyPair() []JWK {
	ctxBg := context.Background()
	KeyPairsFromDB, err := ent.Client.OpenIDKey.Query().Where(openidkey.IsActiveEQ(true)).Order(openidkey.ByCreatedAt(sql.OrderDesc())).All(ctxBg)
	ResultKeyPairs := make([]JWK, 0)
	if err == nil {
		for _, k := range KeyPairsFromDB {
			ResultKeyPairs = append(ResultKeyPairs,
				JWK{
					Kid: k.Kid,
					Kty: "RSA",
					Use: "sig",
					Alg: "RS256",
					N:   k.Modulus,
					E:   k.Exponent,
				})
		}
	}
	return ResultKeyPairs
}
