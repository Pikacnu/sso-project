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
	Scope     string    // 該 Token 實際擁有的權限範圍
}

// User 使用者資訊
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

// SocialAccount 第三方登入關聯表
type SocialAccount struct {
	BaseSchema
	ID         string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	CreatedAt  time.Time `gorm:"autoCreateTime"`
	UpdatedAt  time.Time `gorm:"autoUpdateTime"`
	UserID     string    `gorm:"index;not null"`
	User       User      `gorm:"foreignKey:UserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Provider   string    `gorm:"index;not null"`       // "google", "discord"
	ProviderID string    `gorm:"uniqueIndex;not null"` // 第三方的唯一 ID (例如 Discord Snowflake)
}

// Client OAuth2 客戶端應用
type Client struct {
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

// AccessToken 存取權杖
type AccessToken struct {
	BaseWithExpires
	Token    string `gorm:"uniqueIndex;not null"`
	ClientID string `gorm:"index;not null"`
	Client   Client `gorm:"foreignKey:ClientID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	UserID   string `gorm:"index;not null"`
	User     User   `gorm:"foreignKey:UserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

// RefreshToken 重新整理權杖
type RefreshToken struct {
	BaseWithExpires
	ID        string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
	ExpiresAt time.Time `gorm:"not null"`
	Scope     string    // 該 Token 實際擁有的權限範圍
	Token     string    `gorm:"uniqueIndex;not null"`
	ClientID  string    `gorm:"index;not null"`
	Client    Client    `gorm:"foreignKey:ClientID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	UserID    string    `gorm:"index;not null"`
	User      User      `gorm:"foreignKey:UserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

// AuthorizationCode 授權碼
type AuthorizationCode struct {
	BaseWithExpires
	ID          string    `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	CreatedAt   time.Time `gorm:"autoCreateTime"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime"`
	ExpiresAt   time.Time `gorm:"not null"`
	Scope       string    // 該 Token 實際擁有的權限範圍
	Code        string    `gorm:"uniqueIndex;not null"`
	ClientID    string    `gorm:"index;not null"`
	Client      Client    `gorm:"foreignKey:ClientID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	UserID      string    `gorm:"index;not null"`
	User        User      `gorm:"foreignKey:UserID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	RedirectURI string    `gorm:"not null"`
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
