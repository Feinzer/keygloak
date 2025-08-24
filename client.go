package keygloak

import (
	"fmt"
	"os"
)

type KClient struct {
	Domain       string
	Realm        string
	BaseURL      string
	AdminURL     string
	ClientID     string
	ClientSecret string
	ClientToken  *KToken
}

// Initialize your Keycloak client from your instance config
func New(domain string, realm string) *KClient {
	baseUrl := fmt.Sprintf("https://%s/realms/%s", domain, realm)
	adminUrl := fmt.Sprintf("https://%s/admin/realms/%s", domain, realm)
	return &KClient{
		Domain:   domain,
		Realm:    realm,
		BaseURL:  baseUrl,
		AdminURL: adminUrl,
	}
}

// Initializes your Keycloak instance config from the following environment variables.
//   - KC_DOMAIN=example.org
//   - KC_REALM=example
func NewFromEnv() (*KClient, error) {
	domain, ok := os.LookupEnv("KC_DOMAIN")
	if !ok {
		return nil, envNotSet("KC_DOMAIN")
	}

	realm, ok := os.LookupEnv("KC_REALM")
	if !ok {
		return nil, envNotSet("KC_REALM")
	}

	baseUrl := fmt.Sprintf("https://%s/realms/%s", domain, realm)
	adminUrl := fmt.Sprintf("https://%s/admin/realms/%s", domain, realm)

	return &KClient{
		Domain:   domain,
		Realm:    realm,
		BaseURL:  baseUrl,
		AdminURL: adminUrl,
	}, nil
}

// Authenticates your Keycloak client using the clientId and clientSecret values
func (client *KClient) Authenticate(clientId string, clientSecret string) error {
	token, err := client.GetOpenIDToken(
		KGrantTypeClient,
		&KTokenOpts{
			ClientID:     clientId,
			ClientSecret: clientSecret,
		},
	)
	if err != nil {
		return err
	}

	client.ClientID = clientId
	client.ClientSecret = clientSecret
	client.ClientToken = token

	return nil
}
