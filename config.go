package kmssdk

// AuthenticationType is the authentication mode of a deployment, discovered
// from GET /configs/auth.
type AuthenticationType string

// OAuth2Provider identifies the IdP family of an OAuth2 deployment.
type OAuth2Provider string

// KeycloakMode says whether Keys&More manages the Keycloak users itself
// (MANAGED) or users are administered directly in Keycloak (NON_MANAGED).
type KeycloakMode string

// Known values of the configuration enums.
const (
	AuthenticationTypeOAuth2      AuthenticationType = "OAUTH2"
	AuthenticationTypeSelfManaged AuthenticationType = "SELF_MANAGED"
	OAuth2ProviderKeycloak        OAuth2Provider     = "KEYCLOAK"
	OAuth2ProviderOther           OAuth2Provider     = "OTHER"
	KeycloakModeManaged           KeycloakMode       = "MANAGED"
)

// Config is the authentication configuration returned by the server's public
// /configs/auth endpoint (AuthenticationConfigModel).
type Config struct {
	UniverseAsUsernamePrefix *bool              `json:"universeAsUsernamePrefix"`
	Type                     AuthenticationType `json:"type"`
	OAuth2                   *OAuth2Config      `json:"oauth2,omitempty"`
}

// OAuth2Config carries the OAuth2 coordinates when Config.Type is OAUTH2.
type OAuth2Config struct {
	Provider OAuth2Provider        `json:"provider"`
	Claims   OAuth2ClaimsConfig    `json:"claims"`
	Keycloak *OAuth2KeycloakConfig `json:"keycloak,omitempty"`
	Other    *OAuth2OtherConfig    `json:"other,omitempty"`
}

// OAuth2ClaimsConfig maps JWT claim paths to the KMS identity values
// (username, universe, policy).
type OAuth2ClaimsConfig struct {
	Username string `json:"username"`
	Universe string `json:"universe"`
	Policy   string `json:"policy"`
}

// OAuth2KeycloakConfig is set when the provider is KEYCLOAK. URL may be
// absolute, root-relative, or relative to the KMS base URL; Connect resolves
// it accordingly.
type OAuth2KeycloakConfig struct {
	URL      string       `json:"url"`
	Realm    string       `json:"realm"`
	ClientID string       `json:"clientId"`
	Mode     KeycloakMode `json:"mode"`
}

// OAuth2OtherConfig is set when the provider is OTHER (generic OAuth2/OIDC,
// e.g. Auth0 or Okta). TokenEndpoint may be absolute or relative to URL;
// AccessTokenProperty names the token-response property carrying the usable
// token, in camel case (default "accessToken", e.g. "idToken" when the IdP's
// id_token is the one to use).
type OAuth2OtherConfig struct {
	URL                   string `json:"url"`
	ClientID              string `json:"clientId"`
	Audience              string `json:"audience"`
	TokenEndpoint         string `json:"tokenEndpoint"`
	AuthorizationEndpoint string `json:"authorizationEndpoint"`
	LogoutEndpoint        string `json:"logoutEndpoint"`
	RedirectURI           string `json:"redirectUri"`
	AccessTokenProperty   string `json:"accessTokenProperty"`
}
