package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// OpenIDKey holds JWKS keys used by the server.
type OpenIDKey struct{ ent.Schema }

func (OpenIDKey) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.Nil).Annotations(
			entsql.DefaultExpr("uuidv7()"),
		).Immutable().Unique(),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.String("kid").Unique(),
		field.String("private_key").StorageKey("private_key"),
		field.String("public_key").StorageKey("public_key"),
		field.String("modulus"),
		field.String("exponent"),
		field.Bool("is_active").Default(true),
		field.Time("expires_at").Optional().Nillable(),
	}
}

func (OpenIDKey) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("expires_at"),
		index.Fields("is_active"),
		index.Fields("kid").Unique(),
		index.Fields("kid", "is_active"),
	}
}

func (OpenIDKey) Edges() []ent.Edge { return nil }
