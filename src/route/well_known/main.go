package wellknown

import (
	"github.com/gin-gonic/gin"
)

func RegistrerWellKnownRoutes(router *gin.Engine) {
	routerGroup := router.Group("/.well-known")
	routerGroup.GET("/openid-configuration", openidConfigurationHandler)
	routerGroup.GET("/jwks.json", jwksHandler)

}

type OpenIDConfiguration struct {
	Issuer                                     string   `json:"issuer"`                                                     // REQUIRED
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`                                     // REQUIRED
	TokenEndpoint                              string   `json:"token_endpoint"`                                             // REQUIRED (unless OP only supports Implicit Flow)
	UserInfoEndpoint                           string   `json:"userinfo_endpoint"`                                          // RECOMMENDED
	JWKSURI                                    string   `json:"jwks_uri"`                                                   // REQUIRED
	RegistrationEndpoint                       string   `json:"registration_endpoint,omitempty"`                            // RECOMMENDED
	ScopesSupported                            []string `json:"scopes_supported,omitempty"`                                 // RECOMMENDED
	ResponseTypesSupported                     []string `json:"response_types_supported"`                                   // REQUIRED
	ResponseModesSupported                     []string `json:"response_modes_supported,omitempty"`                         // OPTIONAL
	GrantTypesSupported                        []string `json:"grant_types_supported,omitempty"`                            // OPTIONAL
	AcrValuesSupported                         []string `json:"acr_values_supported,omitempty"`                             // OPTIONAL
	SubjectTypesSupported                      []string `json:"subject_types_supported"`                                    // REQUIRED
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`                      // REQUIRED (must include RS256)
	IDTokenEncryptionAlgValuesSupported        []string `json:"id_token_encryption_alg_values_supported,omitempty"`         // OPTIONAL
	IDTokenEncryptionEncValuesSupported        []string `json:"id_token_encryption_enc_values_supported,omitempty"`         // OPTIONAL
	UserInfoSigningAlgValuesSupported          []string `json:"userinfo_signing_alg_values_supported,omitempty"`            // OPTIONAL
	UserInfoEncryptionAlgValuesSupported       []string `json:"userinfo_encryption_alg_values_supported,omitempty"`         // OPTIONAL
	UserInfoEncryptionEncValuesSupported       []string `json:"userinfo_encryption_enc_values_supported,omitempty"`         // OPTIONAL
	RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported,omitempty"`      // OPTIONAL (servers SHOULD support none and RS256)
	RequestObjectEncryptionAlgValuesSupported  []string `json:"request_object_encryption_alg_values_supported,omitempty"`   // OPTIONAL
	RequestObjectEncryptionEncValuesSupported  []string `json:"request_object_encryption_enc_values_supported,omitempty"`   // OPTIONAL
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported,omitempty"`            // OPTIONAL
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"` // OPTIONAL (servers SHOULD support RS256)
	DisplayValuesSupported                     []string `json:"display_values_supported,omitempty"`                         // OPTIONAL
	ClaimTypesSupported                        []string `json:"claim_types_supported,omitempty"`                            // OPTIONAL
	ClaimsSupported                            []string `json:"claims_supported,omitempty"`                                 // RECOMMENDED
	ServiceDocumentation                       string   `json:"service_documentation,omitempty"`                            // OPTIONAL
	ClaimsLocalesSupported                     []string `json:"claims_locales_supported,omitempty"`                         // OPTIONAL
	UILocalesSupported                         []string `json:"ui_locales_supported,omitempty"`                             // OPTIONAL
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported,omitempty"`                       // OPTIONAL (default: false)
	RequestParameterSupported                  bool     `json:"request_parameter_supported,omitempty"`                      // OPTIONAL (default: false)
	RequestURIParameterSupported               bool     `json:"request_uri_parameter_supported,omitempty"`                  // OPTIONAL (default: true)
	RequireRequestURIRegistration              bool     `json:"require_request_uri_registration,omitempty"`                 // OPTIONAL (default: false)
	OPPolicyURI                                string   `json:"op_policy_uri,omitempty"`                                    // OPTIONAL
	OPTosURI                                   string   `json:"op_tos_uri,omitempty"`                                       // OPTIONAL
}

func openidConfigurationHandler(ctx *gin.Context) {
	issuer := getIssuer(ctx)
	authorizationEndpoint := issuer + "/auth/authorize"
	tokenEndpoint := issuer + "/auth/token"
	userInfoEndpoint := issuer + "/auth/userinfo"
	jwksURI := issuer + "/.well-known/jwks.json"
	scopesSupported := []string{"openid", "profile", "email"}
	responseTypesSupported := []string{"code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"}
	responseModesSupported := []string{"query", "fragment", "form_post"}
	grantTypesSupported := []string{"authorization_code", "refresh_token", "password", "client_credentials"}
	subjectTypesSupported := []string{"public"}
	idTokenSigningAlgValuesSupported := []string{"RS256"}
	tokenEndpointAuthMethodsSupported := []string{"client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt"}
	claimsSupported := []string{"sub", "name", "email"}

	config := OpenIDConfiguration{
		Issuer:                            issuer,
		AuthorizationEndpoint:             authorizationEndpoint,
		TokenEndpoint:                     tokenEndpoint,
		UserInfoEndpoint:                  userInfoEndpoint,
		JWKSURI:                           jwksURI,
		ResponseTypesSupported:            responseTypesSupported,
		ResponseModesSupported:            responseModesSupported,
		GrantTypesSupported:               grantTypesSupported,
		SubjectTypesSupported:             subjectTypesSupported,
		IDTokenSigningAlgValuesSupported:  idTokenSigningAlgValuesSupported,
		TokenEndpointAuthMethodsSupported: tokenEndpointAuthMethodsSupported,
		ClaimsSupported:                   claimsSupported,
		ScopesSupported:                   scopesSupported,
	}
	ctx.JSON(200, config)
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kid string `json:"kid"` // Key ID
	Kty string `json:"kty"` // Key Type (e.g., RSA)
	Use string `json:"use"` // Public Key Use (e.g., sig for signature)
	Alg string `json:"alg"` // Algorithm (e.g., RS256)
	N   string `json:"n"`   // Modulus for RSA
	E   string `json:"e"`   // Exponent for RSA
}

func jwksHandler(ctx *gin.Context) {
	jwks := JWKS{
		Keys: []JWK{
			{
				Kid: "1",
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
				N:   "",
				E:   "",
			},
		},
	}
	ctx.JSON(200, jwks)
}

func getIssuer(ctx *gin.Context) string {
	return "https://" + ctx.Request.Host
}
