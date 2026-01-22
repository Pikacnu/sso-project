package db

import (
	"time"
)

type BaseSchema struct {
	ID        string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}

type BaseWithExpires struct {
	BaseSchema
	ID        string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
	ExpiresAt time.Time `gorm:"not null"`
	Scope     string    // The actual scope owned by this token
}

// User User information
type User struct {
	BaseSchema
	ID        string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
	Username  string    `gorm:"uniqueIndex;not null"`
	Email     string    `gorm:"uniqueIndex;not null"`
	Password  string    //`gorm:"not null"`
	Avatar    string
}

// SocialAccount Third-party login association table
type SocialAccount struct {
	BaseSchema
	ID         string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	CreatedAt  time.Time `gorm:"autoCreateTime"`
	UpdatedAt  time.Time `gorm:"autoUpdateTime"`
	UserID     string    `gorm:"index;not null"`
	User       User      `gorm:"foreignKey:UserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Provider   string    `gorm:"index;not null"`       // "google", "discord"
	ProviderID string    `gorm:"uniqueIndex;not null"` // Third-party unique ID (e.g., Discord Snowflake)
}

// OAuthClient OAuth2 client application
type OAuthClient struct {
	BaseSchema
	ID            string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	CreatedAt     time.Time `gorm:"autoCreateTime"`
	UpdatedAt     time.Time `gorm:"autoUpdateTime"`
	Secret        string    `gorm:"not null"`
	Domain        string
	RedirectURIs  string `gorm:"not null"`
	AppName       string
	AllowedScopes string `gorm:"default:'openid profile'"`
	OwnerID       string `gorm:"index"`
	IsActive      bool   `gorm:"default:true"`
	LogoURL       string
}

// AccessToken Access token
type AccessToken struct {
	BaseWithExpires
	ID        string      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	CreatedAt time.Time   `gorm:"autoCreateTime"`
	UpdatedAt time.Time   `gorm:"autoUpdateTime"`
	ExpiresAt time.Time   `gorm:"not null"`
	Scope     string      // The actual scope owned by this token
	Token     string      `gorm:"uniqueIndex;not null"`
	ClientID  string      `gorm:"index;not null"`
	Client    OAuthClient `gorm:"foreignKey:ClientID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	UserID    string      `gorm:"index;not null"`
	User      User        `gorm:"foreignKey:UserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

// RefreshToken Refresh token
type RefreshToken struct {
	BaseWithExpires
	ID            string      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	CreatedAt     time.Time   `gorm:"autoCreateTime"`
	UpdatedAt     time.Time   `gorm:"autoUpdateTime"`
	ExpiresAt     time.Time   `gorm:"not null"`
	AccessTokenID string      `gorm:"index;not null"`
	AccessToken   AccessToken `gorm:"foreignKey:AccessTokenID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Scope         string      // The actual scope owned by this token
	Token         string      `gorm:"uniqueIndex;not null"`
	ClientID      string      `gorm:"index;not null"`
	Client        OAuthClient `gorm:"foreignKey:ClientID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	UserID        string      `gorm:"index;not null"`
	User          User        `gorm:"foreignKey:UserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

// AuthorizationCode Authorization code
type AuthorizationCode struct {
	BaseWithExpires
	ID          string      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	CreatedAt   time.Time   `gorm:"autoCreateTime"`
	UpdatedAt   time.Time   `gorm:"autoUpdateTime"`
	ExpiresAt   time.Time   `gorm:"not null"`
	Code        string      `gorm:"uniqueIndex;not null"`
	ClientID    string      `gorm:"index;not null"`
	Client      OAuthClient `gorm:"foreignKey:ClientID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	UserID      string      `gorm:"index;not null"`
	User        User        `gorm:"foreignKey:UserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	RedirectURI string      `gorm:"not null"`
	Scope       string      // The actual scope owned by this token
}

// Session Server-side session record
type Session struct {
	ID        string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
	UserID    string    `gorm:"index;not null"`
	User      User      `gorm:"foreignKey:UserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	UserAgent string
	IPAddress string
	ExpiresAt time.Time `gorm:"index;not null"`
	IsRevoked bool      `gorm:"default:false"`
}

// OAuthFlow tracks an ongoing OAuth2 login flow between a Client, SSO, and an external Provider
type OAuthFlow struct {
	BaseWithExpires
	// ClientState is the original 'state' parameter provided by the Client application
	ClientState string `gorm:"not null"`

	ClientID string      `gorm:"index;not null"`
	Client   OAuthClient `gorm:"foreignKey:ClientID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`

	ID string `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`

	UserID string `gorm:"index;not null"`
	User   User   `gorm:"foreignKey:UserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`

	RedirectURI string    `gorm:"not null"`
	Scope       string    `gorm:"not null"`
	Provider    string    `gorm:"not null"` // e.g., "discord", "google"
	ExpiresAt   time.Time `gorm:"index;not null"`
}

type Scoop struct {
	ID        string      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	CreatedAt time.Time   `gorm:"autoCreateTime"`
	UpdatedAt time.Time   `gorm:"autoUpdateTime"`
	ClientID  string      `gorm:"index;not null"`
	Client    OAuthClient `gorm:"foreignKey:ClientID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`

	// Key is the unique identifier for the scope, e.g., "storage.user"
	Key  string `gorm:"index;not null"`
	Data string `gorm:"type:text"` // JSON data corresponding to this scope

	// Optional UserID if the data is user-specific
	UserID *string `gorm:"index"`
	User   *User   `gorm:"foreignKey:UserID;references:ID"`
}

/*
Scoop Example (1 row per scope):

If a service (ClientID) wants to share multiple types of user data, multiple records will be created:

Record 1:
{
	Key:    "storage.user",
	Data:   "{\"id\": \"user-123\", \"name\": \"John\"}",
	UserID: "user-uuid",
	ClientID: "client-uuid"
}

Record 2:
{
	Key:    "storage.config",
	Data:   "{\"theme\": \"dark\", \"lang\": \"en-US\"}",
	UserID: "user-uuid",
	ClientID: "client-uuid"
}

Usage:
	1. Check if the Scope in AccessToken includes "storage.user".
	2. If included, query the Scoop content where Key is "storage.user".
*/
