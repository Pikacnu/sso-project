package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Permission represents a granular permission in RBAC.
type Permission struct{ ent.Schema }

func (Permission) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.Nil).Default(DefaultUUID).Immutable().Unique(),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.String("key").Unique(),
		field.String("description").Optional().Nillable(),
	}
}

func (Permission) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("key").Unique(),
	}
}

func (Permission) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("roles", Role.Type).Ref("permissions"),
	}
}
