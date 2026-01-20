package providors

import (
	"fmt"
	"sso-server/src/config"

	"github.com/ravener/discord-oauth2"
	"golang.org/x/oauth2"

	"golang.org/x/oauth2/google"
)

var cfg *config.Env = config.NewEnvFromEnv()

var (
	DiscordOAuthConfig = &oauth2.Config{
		ClientID:     cfg.DiscordClientID,
		ClientSecret: cfg.DiscordClientSecret,
		RedirectURL:  GetAuthCallbackUrl("discord"),
		Scopes:       []string{discord.ScopeIdentify, discord.ScopeEmail, discord.ScopeGuilds},
		Endpoint:     discord.Endpoint,
	}

	GoogleOAuthConfig = &oauth2.Config{
		ClientID:     cfg.GoogleClientID,
		ClientSecret: cfg.GoogleClientSecret,
		RedirectURL:  GetAuthCallbackUrl("google"),
		Scopes:       []string{"openid", "profile", "email"},
		Endpoint:     google.Endpoint,
	}
)

func GetAuthCallbackUrl(provider string) string {
	protocol := "http"
	if cfg.Port == "443" {
		protocol = "https"
	}
	return fmt.Sprintf("%s://%s:%s/auth/%s/callback", protocol, cfg.Hostname, cfg.Port, provider)
}
