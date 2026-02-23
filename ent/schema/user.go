package schema

import (
	"time"

	"entgo.io/ent"
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
		field.UUID("id", uuid.Nil).Default(DefaultUUID).Immutable().Unique(),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.String("username").Unique(),
		field.String("email").Unique(),
		field.Bool("email_verified").Default(false),
		field.String("email_verification_token").Optional().Nillable(),
		field.Time("email_verification_expires_at").Optional().Nillable(),
		field.String("password").Optional().Nillable(),
		field.String("avatar").Optional().Nillable(),
		field.String("password_reset_token").Optional().Nillable(),
		field.Time("password_reset_expires_at").Optional().Nillable(),
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
		edge.To("roles", Role.Type),
	}
}
