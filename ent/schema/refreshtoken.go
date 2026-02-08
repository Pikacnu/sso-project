package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// RefreshToken holds refresh token records.
type RefreshToken struct{ ent.Schema }

func (RefreshToken) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").DefaultFunc(func() string { return uuid.NewString() }).Immutable(),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.Time("expires_at"),
		field.String("access_token_id"),
		field.String("scope").Optional().Nillable(),
		field.String("token").Unique(),
		field.String("client_id"),
		field.String("user_id"),
	}
}

func (RefreshToken) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "client_id", "access_token_id"),
		index.Fields("expires_at"),
	}
}

func (RefreshToken) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("access_token", AccessToken.Type).Ref("refresh_tokens").Required().Unique().Field("access_token_id"),
		edge.From("client", OAuthClient.Type).Ref("refresh_tokens").Required().Unique().Field("client_id"),
		edge.From("user", User.Type).Ref("refresh_tokens").Required().Unique().Field("user_id"),
	}
}
