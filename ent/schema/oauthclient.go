package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// OAuthClient represents a registered OAuth2 client application.
type OAuthClient struct{ ent.Schema }

func (OAuthClient) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").DefaultFunc(func() string { return uuid.NewString() }).Immutable(),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.String("secret"),
		field.String("domain").Optional().Nillable(),
		field.String("redirect_uris"),
		field.String("app_name").Optional().Nillable(),
		field.String("allowed_scopes").Default("openid profile"),
		field.String("owner_id").Optional().Nillable(),
		field.Bool("is_active").Default(true),
		field.String("logo_url").Optional().Nillable(),
	}
}

func (OAuthClient) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("owner_id"),
	}
}

func (OAuthClient) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("owner", User.Type).Ref("oauth_clients").Field("owner_id").Unique(),
		edge.To("access_tokens", AccessToken.Type),
		edge.To("refresh_tokens", RefreshToken.Type),
		edge.To("authorization_codes", AuthorizationCode.Type),
		edge.To("scopes", Scope.Type),
		edge.To("oauth_flows", OAuthFlow.Type),
	}
}
