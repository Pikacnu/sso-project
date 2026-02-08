package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Scope stores per-client scope data (key/data pairs).
type Scope struct{ ent.Schema }

func (Scope) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").DefaultFunc(func() string { return uuid.NewString() }).Immutable(),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.String("client_id"),
		field.String("key"),
		field.String("data").Optional().Nillable().StorageKey("data"),
		field.String("user_id").Optional().Nillable(),
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
