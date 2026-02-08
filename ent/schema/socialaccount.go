package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// SocialAccount maps third-party provider accounts to local users.
type SocialAccount struct{ ent.Schema }

func (SocialAccount) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").DefaultFunc(func() string { return uuid.NewString() }).Immutable(),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.String("user_id"),
		field.String("provider"),
		field.String("provider_id").Unique(),
	}
}

func (SocialAccount) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "provider"),
	}
}

func (SocialAccount) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).Ref("social_accounts").Required().Unique().Field("user_id"),
	}
}
