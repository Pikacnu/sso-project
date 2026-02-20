package schema

import "github.com/google/uuid"

// DefaultUUID generates a UUIDv7 when available, falling back to UUIDv4.
func DefaultUUID() uuid.UUID {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.New()
	}
	return id
}
