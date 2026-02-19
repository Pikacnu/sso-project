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

// Scope stores per-client scope data (key/data pairs).
type Scope struct{ ent.Schema }

func (Scope) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.Nil).Annotations(
			entsql.DefaultExpr("uuidv7()"),
		).Immutable().Unique(),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.UUID("client_id", uuid.Nil),
		field.String("key"),
		field.String("description").Optional().Nillable(),
		field.Bool("is_external").Default(false),
		field.String("external_endpoint").Optional().Nillable(),
		field.String("external_method").Optional().Nillable(),
		field.String("auth_type").Optional().Nillable(),
		field.String("auth_secret_env").Optional().Nillable(),
		field.String("json_schema").Optional().Nillable(),
		field.String("data").Optional().Nillable().StorageKey("data"),
		field.UUID("user_id", uuid.Nil).Optional().Nillable(),
	}
}

func (Scope) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("client_id", "key").Unique(),
		index.Fields("user_id", "key").Unique(),
	}
}

func (Scope) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("client", OAuthClient.Type).Ref("scopes").Required().Unique().Field("client_id"),
		edge.From("user", User.Type).Ref("scopes").Unique().Field("user_id"),
	}
}
