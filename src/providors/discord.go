package providors

// DiscordUser represents a Discord user object.
// Documentation: https://discord.com/developers/docs/resources/user#user-object
type DiscordUser struct {
	ID                   string      `json:"id"`
	Username             string      `json:"username"`
	Discriminator        string      `json:"discriminator"`
	GlobalName           *string     `json:"global_name"`
	Avatar               *string     `json:"avatar"`
	Bot                  bool        `json:"bot,omitempty"`
	System               bool        `json:"system,omitempty"`
	MFAEnabled           bool        `json:"mfa_enabled,omitempty"`
	Banner               *string     `json:"banner"`
	AccentColor          int         `json:"accent_color,omitempty"`
	Locale               string      `json:"locale,omitempty"`
	Verified             bool        `json:"verified,omitempty"`
	Email                *string     `json:"email"`
	Flags                int         `json:"flags,omitempty"`
	PremiumType          int         `json:"premium_type,omitempty"`
	PublicFlags          int         `json:"public_flags,omitempty"`
	AvatarDecorationData interface{} `json:"avatar_decoration_data"`
	Collectibles         interface{} `json:"collectibles"`
	PrimaryGuild         interface{} `json:"primary_guild"`
}
