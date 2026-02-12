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

// AccessToken holds access token records.
type AccessToken struct{ ent.Schema }

func (AccessToken) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.Nil).Annotations(
			entsql.DefaultExpr("uuidv7()"),
		).Immutable().Unique(),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.Time("expires_at"),
		field.String("scope").Optional().Nillable(),
		field.String("token").Unique(),
		field.UUID("client_id", uuid.Nil),
		field.UUID("user_id", uuid.Nil),
	}
}

func (AccessToken) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "client_id"),
		index.Fields("expires_at"),
	}
}

func (AccessToken) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("client", OAuthClient.Type).Ref("access_tokens").Required().Unique().Field("client_id"),
		edge.From("user", User.Type).Ref("access_tokens").Required().Unique().Field("user_id"),
		edge.To("refresh_tokens", RefreshToken.Type),
	}
}
