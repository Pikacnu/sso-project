package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// AuthorizationCode represents a short-lived auth code.
type AuthorizationCode struct{ ent.Schema }

func (AuthorizationCode) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").DefaultFunc(func() string { return uuid.NewString() }).Immutable(),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.Time("expires_at"),
		field.String("code").Unique(),
		field.String("client_id"),
		field.String("user_id"),
		field.String("redirect_uri"),
		field.String("scope").Optional().Nillable(),
		field.String("code_challenge").Optional().Nillable(),
		field.String("code_challenge_method").Optional().Nillable(),
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
