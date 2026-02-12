package utils

import "github.com/google/uuid"

func GenerateUUIDStringV7() (string, error) {
	uuid, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	return uuid.String(), nil
}

func GenerateUUIDV7StringPanic() string {
	uuidString, err := GenerateUUIDStringV7()
	if err != nil {
		panic(err)
	}
	return uuidString
}

func GenerateUUIDV7() (uuid.UUID, error) {
	return uuid.NewV7()
}

func GenerateUUIDV7Panic() uuid.UUID {
	uuid, err := GenerateUUIDV7()
	if err != nil {
		panic(err)
	}
	return uuid
}
