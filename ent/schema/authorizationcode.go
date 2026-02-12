package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// AuthorizationCode represents a short-lived auth code.
type AuthorizationCode struct{ ent.Schema }

func (AuthorizationCode) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.Nil).Annotations(
			entsql.DefaultExpr("uuidv7()"),
		).Immutable().Unique(),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.Time("expires_at"),
		field.String("code").Unique(),
		field.UUID("client_id", uuid.Nil),
		field.UUID("user_id", uuid.Nil),
		field.String("redirect_uri"),
		field.String("scope").Optional().Nillable(),
		field.String("code_challenge").Optional().Nillable(),
		field.String("code_challenge_method").Optional().Nillable(),
		field.String("nonce").Optional().Nillable(),
	}
}

func (AuthorizationCode) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "client_id"),
		index.Fields("expires_at"),
	}
}

func (AuthorizationCode) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("client", OAuthClient.Type).Ref("authorization_codes").Required().Unique().Field("client_id"),
		edge.From("user", User.Type).Ref("authorization_codes").Required().Unique().Field("user_id"),
	}
}
