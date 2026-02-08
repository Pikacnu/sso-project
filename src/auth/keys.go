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

	ent "sso-server/ent/generated"
	"sso-server/ent/generated/openidkey"
	dbpkg "sso-server/src/db"

	"entgo.io/ent/dialect/sql"
)

var currentKeyPair *KeyPair

func init() {
	ctxBg := context.Background()
	queryKeyPair, err := dbpkg.Client.OpenIDKey.Query().Order(openidkey.ByCreatedAt(sql.OrderDesc())).Only(ctxBg)
	if err == nil && queryKeyPair != nil {
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
		if queryKeyPair != nil && queryKeyPair.PublicKey != "" {
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
	} else if !ent.IsNotFound(err) {
		// Only panic if error is not NotFound (which is expected for first run)
		panic("failed to query openidkey: " + err.Error())
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

	// Persist using Ent
	ctx := context.Background()
	if _, err := dbpkg.Client.OpenIDKey.Create().
		SetKid(kid).
		SetPrivateKey(string(privateKeyPEM)).
		SetPublicKey(string(publicKeyPEM)).
		SetModulus(keyPair.Modulus).
		SetExponent(keyPair.Exponent).
		SetIsActive(true).
		Save(ctx); err != nil {
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
	ctxBg := context.Background()
	cutoffTime := time.Now().AddDate(0, 0, -expireDays)
	_, err := dbpkg.Client.OpenIDKey.Delete().Where(openidkey.CreatedAtLT(cutoffTime)).Exec(ctxBg)
	if err != nil {
		// Log error but don't panic
	}
}
