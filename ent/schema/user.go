package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
)

// User holds the schema definition for the User entity.
type User struct {
	ent.Schema
}

func (User) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.Nil).Annotations(
			entsql.DefaultExpr("uuid_generate_v7()"),
		).Immutable().Unique(),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.String("username").Unique(),
		field.String("email").Unique(),
		field.String("password").Optional().Nillable(),
		field.String("avatar").Optional().Nillable(),
	}
}

func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("social_accounts", SocialAccount.Type),
		edge.To("access_tokens", AccessToken.Type),
		edge.To("refresh_tokens", RefreshToken.Type),
		edge.To("authorization_codes", AuthorizationCode.Type),
		edge.To("sessions", Session.Type),
		edge.To("scopes", Scope.Type),
		edge.To("oauth_flows", OAuthFlow.Type),
		edge.To("oauth_clients", OAuthClient.Type),
	}
}
