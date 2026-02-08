package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"

	"sso-server/src/db"

	"gorm.io/gorm"
)

var currentKeyPair *KeyPair

func init() {
	var queryKeyPair db.OpenIDKey
	result := db.DBConnection.Order("created_at desc").First(&queryKeyPair)
	if result.Error == nil {
		// Try to load private key PEM first
		if queryKeyPair.PrivateKey != "" {
			block, _ := pem.Decode([]byte(queryKeyPair.PrivateKey))
			if block != nil {
				if priv, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
					currentKeyPair = &KeyPair{
						PrivateKey: priv,
						PublicKey:  &priv.PublicKey,
						Modulus:    queryKeyPair.Modulus,
						Exponent:   queryKeyPair.Exponent,
					}
					return
				}
			}
		}

		// Fallback: try to parse public key PEM
		if queryKeyPair.PublicKey != "" {
			blockPub, _ := pem.Decode([]byte(queryKeyPair.PublicKey))
			if blockPub != nil {
				if pubIf, err := x509.ParsePKIXPublicKey(blockPub.Bytes); err == nil {
					if pub, ok := pubIf.(*rsa.PublicKey); ok {
						currentKeyPair = &KeyPair{
							PrivateKey: nil,
							PublicKey:  pub,
							Modulus:    queryKeyPair.Modulus,
							Exponent:   queryKeyPair.Exponent,
						}
						return
					}
				}
			}
		}
	}

	// No key found or failed to parse: generate and persist a new keypair
	kp, err := generateKeys()
	if err != nil {
		panic(err)
	}
	currentKeyPair = kp
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
}

func generateKeys() (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	publicKey := &privateKey.PublicKey
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	keyPair := &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Modulus:    encodeToBase64URL(publicKey.N.Bytes()),
		Exponent:   encodeToBase64URL(big.NewInt(int64(publicKey.E)).Bytes()),
	}

	err = os.WriteFile("private_key.pem", privateKeyPEM, 0600)
	if err != nil {
		return nil, err
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

	// generate a kid from modulus (short and deterministic)
	kid := encodeToBase64URL(publicKey.N.Bytes())

	dbKey := db.OpenIDKey{
		Kid:        kid,
		PrivateKey: string(privateKeyPEM),
		PublicKey:  string(publicKeyPEM),
		Modulus:    keyPair.Modulus,
		Exponent:   keyPair.Exponent,
		IsActive:   true,
	}

	if err := db.DBConnection.Create(&dbKey).Error; err != nil {
		return nil, err
	}

	// set in-memory current key pair
	currentKeyPair = keyPair

	return keyPair, nil
}

func encodeToBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func cleanupOldKeys() {
	expireDays := cfg.OpenIDKeyExpireDays
	db.DBConnection.Where("created_at <", gorm.Expr("NOW() - INTERVAL '? days'", expireDays)).Delete(&db.OpenIDKey{})
}
