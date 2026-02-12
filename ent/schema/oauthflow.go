package schema

import (
	"sso-server/src/utils"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// OAuthFlow tracks an ongoing OAuth2 login flow.
type OAuthFlow struct{ ent.Schema }

func (OAuthFlow) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").DefaultFunc(func() string { return utils.GenerateUUIDV7StringPanic() }).Immutable(),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.String("client_state"),
		field.String("client_id"),
		field.UUID("user_id", uuid.Nil),
		field.String("redirect_uri"),
		field.String("scope"),
		field.String("provider"),
		field.Time("expires_at"),
		field.String("code_challenge").Optional().Nillable(),
		field.String("code_challenge_method").Optional().Nillable(),
		field.String("nonce").Optional().Nillable(),
	}
}

func (OAuthFlow) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "client_id"),
		index.Fields("expires_at"),
	}
}

func (OAuthFlow) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("client", OAuthClient.Type).Ref("oauth_flows").Required().Unique().Field("client_id"),
		edge.From("user", User.Type).Ref("oauth_flows").Required().Unique().Field("user_id"),
	}
}
