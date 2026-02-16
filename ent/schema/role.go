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

// Role represents a role in RBAC.
type Role struct{ ent.Schema }

func (Role) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.Nil).Annotations(
			entsql.DefaultExpr("uuidv7()"),
		).Immutable().Unique(),
		field.Time("created_at").Default(time.Now).Immutable(),
		field.Time("updated_at").Default(time.Now).UpdateDefault(time.Now),
		field.String("name").Unique(),
		field.String("description").Optional().Nillable(),
	}
}

func (Role) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("name").Unique(),
	}
}

func (Role) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("users", User.Type).Ref("roles"),
		edge.To("permissions", Permission.Type),
	}
}
