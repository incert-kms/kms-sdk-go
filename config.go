package kmssdk

type AuthenticationType string
type Oauth2Provider string
type KeycloakMode string

const (
	AuthenticationTypeOAuth2 AuthenticationType = "OAUTH2"
	Oauth2ProviderKeycloak   Oauth2Provider     = "KEYCLOAK"
	KeycloakModeManaged      KeycloakMode       = "MANAGED"
)

type Config struct {
	UniverseAsUsernamePrefix *bool              `json:"universeAsUsernamePrefix"`
	Type                     AuthenticationType `json:"type"`
	Oauth2                   *Oauth2Config      `json:"oauth2,omitempty"`
}

type Oauth2Config struct {
	Provider Oauth2Provider        `json:"provider"`
	Claims   Oauth2ClaimsConfig    `json:"claims"`
	Keycloak *Oauth2KeycloakConfig `json:"keycloak,omitempty"`
	Other    *Oauth2OtherConfig    `json:"other,omitempty"`
}

type Oauth2ClaimsConfig struct {
	Username string `json:"username"`
	Universe string `json:"universe"`
	Policy   string `json:"policy"`
}

type Oauth2KeycloakConfig struct {
	URL      string       `json:"url"`
	Realm    string       `json:"realm"`
	ClientID string       `json:"clientId"`
	Mode     KeycloakMode `json:"mode"`
}

type Oauth2OtherConfig struct {
	URL                   string `json:"url"`
	ClientID              string `json:"clientId"`
	Audience              string `json:"audience"`
	TokenEndpoint         string `json:"tokenEndpoint"`
	AuthorizationEndpoint string `json:"authorizationEndpoint"`
	LogoutEndpoint        string `json:"logoutEndpoint"`
	RedirectURI           string `json:"redirectUri"`
	AccessTokenProperty   string `json:"accessTokenProperty"`
}
