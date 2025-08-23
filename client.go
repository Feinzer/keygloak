package keygloak

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
)

type KConfig struct {
	Domain   string
	Realm    string
	BaseURL  string
	AdminURL string
}

// Initializes your Keycloak instance config
func Config(domain string, realm string) *KConfig {
	baseUrl := fmt.Sprintf("https://%s/realms/%s", domain, realm)
	adminUrl := fmt.Sprintf("https://%s/admin/realms/%s", domain, realm)
	return &KConfig{
		Domain:   domain,
		Realm:    realm,
		BaseURL:  baseUrl,
		AdminURL: adminUrl,
	}
}

// Initializes your Keycloak instance config from the following environment variables.
//   - KC_DOMAIN=example.org
//   - KC_REALM=example
func ConfigFromEnv() (*KConfig, error) {
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

	return &KConfig{
		Domain:   domain,
		Realm:    realm,
		BaseURL:  baseUrl,
		AdminURL: adminUrl,
	}, nil
}

type KClient struct {
	*KConfig
	Context      context.Context
	ClientID     string
	ClientSecret string
	Access       *KAccessToken
}

type KAccessToken struct {
	Type    string  `json:"token_type"`
	Token   string  `json:"access_token"`
	Refresh *string `json:"refresh_token"`
	Scope   string  `json:"scope"`
}

// Initialize your Keycloak client from your instance config
func New(ctx context.Context, config *KConfig) *KClient {
	return &KClient{
		KConfig: config,
		Context: ctx,
	}
}

type KTokenOpts struct {
	GrantType    string
	ClientID     string
	ClientSecret string
	Scope        string
	RefreshToken *string
	Username     *string
	Password     *string
	Totp         *string
}

// Retrieves a new JWT token from Keycloak using KTokenOptions
func (client *KClient) GetOpenIDToken(opts *KTokenOpts) (*KAccessToken, error) {
	clientId := cmp.Or(client.ClientID, opts.ClientID)
	clientSecret := cmp.Or(client.ClientSecret, opts.ClientSecret)
	scope := cmp.Or(opts.Scope, "openid profile email")

	body := url.Values{}
	body.Add("scope", scope)
	body.Add("client_id", clientId)
	body.Add("client_secret", clientSecret)
	body.Add("grant_type", opts.GrantType)

	if opts.GrantType == "refresh_token" && opts.RefreshToken != nil {
		body.Add("refresh_token", *opts.RefreshToken)
	}
	if opts.GrantType == "password" {
		if opts.Username != nil && opts.Password != nil {
			body.Add("username", *opts.Username)
			body.Add("password", *opts.Password)
		}
		if opts.Totp != nil {
			body.Add("totp", *opts.Totp)
		}
	}

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/%s", client.BaseURL, "protocol/openid-connect/token"),
		strings.NewReader(body.Encode()),
	)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 400 {
		return nil, fmt.Errorf("could not get token")
	}

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var token KAccessToken
	json.Unmarshal(data, &token)

	return &token, nil
}

// Authenticates your Keycloak client using the clientId and clientSecret values
func (client *KClient) Authenticate(clientId string, clientSecret string) error {
	token, err := client.GetOpenIDToken(&KTokenOpts{
		GrantType:    "client_credentials",
		ClientID:     clientId,
		ClientSecret: clientSecret,
	})
	if err != nil {
		return err
	}

	client.ClientID = clientId
	client.ClientSecret = clientSecret
	client.Access = token

	return nil
}

type KUserError struct {
	Message string `json:"errorMessage"`
}

type KUserCredential struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"`
}

type KUserOpts struct {
	Email     string  `json:"email"`
	Username  string  `json:"username"`
	Password  string  `json:"password"`
	FirstName *string `json:"firstName"`
	LastName  *string `json:"lastName"`
}

type KUser struct {
	ID          string             `json:"id"`
	Enabled     bool               `json:"enabled"`
	Email       string             `json:"email"`
	Username    string             `json:"username"`
	FirstName   *string            `json:"firstName"`
	LastName    *string            `json:"lastName"`
	Credentials []*KUserCredential `json:"credentials"`
}

// Creates a new user inside the realm your set in your instance config.
//
// Client has to be previously authenticated using the Authenticate() method*
func (client *KClient) CreateUser(opts *KUserOpts) (*KUser, error) {
	if opts.Password == "" {
		return nil, fmt.Errorf("invalid password")
	}

	user := &KUser{
		Enabled:   true,
		Email:     opts.Email,
		Username:  opts.Username,
		FirstName: opts.FirstName,
		LastName:  opts.LastName,
		Credentials: []*KUserCredential{
			{
				Type:      "password",
				Value:     opts.Password,
				Temporary: false,
			},
		},
	}

	body, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/%s", client.AdminURL, "users"),
		bytes.NewBuffer(body),
	)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", client.Access.Token))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode >= 400 {
		data, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("could not create user")
		}

		var userError KUserError
		json.Unmarshal(data, &userError)
		return nil, fmt.Errorf(userError.Message)
	}

	location, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		return nil, fmt.Errorf("invalid location header: %s", err)
	}

	user.ID = path.Base(location.Path)

	return user, nil
}

type KSignInOpts struct {
	Username string
	Password string
	Totp     *string
}

// Retrieves a token for the user with the provided username, password and optional totp
func (client *KClient) SignInWithPassword(opts *KSignInOpts) (*KAccessToken, error) {
	token, err := client.GetOpenIDToken(&KTokenOpts{
		GrantType: "password",
		Username:  &opts.Username,
		Password:  &opts.Password,
		Totp:      opts.Totp,
	})
	if err != nil {
		return nil, err
	}

	return token, nil
}

type KIntrospectionResponse struct {
	Active    bool   `json:"active"`
	TokenType string `json:"token_type"`
	Scope     string `json:"scope"`
}

// Executes a token introspection
func (client *KClient) IntrospectToken(token string) (*KIntrospectionResponse, bool) {
	body := url.Values{}
	body.Add("client_id", client.ClientID)
	body.Add("client_secret", client.ClientSecret)

	body.Add("token", token)

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/%s", client.BaseURL, "protocol/openid-connect/token/introspect"),
		strings.NewReader(body.Encode()),
	)
	if err != nil {
		return nil, false
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, false
	}

	if res.StatusCode >= 400 {
		return nil, false
	}

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, false
	}

	var response KIntrospectionResponse
	json.Unmarshal(data, &response)

	return &response, response.Active
}

type KValidateOpts struct {
	Token   string
	Refresh *string
}

// Validates a token and tries to refresh it using a refresh_token when provided
func (client *KClient) ValidateToken(opts *KValidateOpts) (*KAccessToken, error) {
	result, ok := client.IntrospectToken(opts.Token)
	if !ok {
		if opts.Refresh == nil {
			return nil, fmt.Errorf("invalid token and no refresh token provided")
		}
		token, err := client.GetOpenIDToken(&KTokenOpts{
			GrantType:    "refresh_token",
			RefreshToken: opts.Refresh,
		})
		if err != nil {
			return nil, err
		}

		return token, nil
	}

	return &KAccessToken{
		Type:    result.TokenType,
		Token:   opts.Token,
		Refresh: opts.Refresh,
		Scope:   result.Scope,
	}, nil
}

type KInvalidateOpts struct {
	Token   string
	Refresh *string
}

// Invalidates the provided token and refresh_token if provided
func (client *KClient) InvalidateToken(opts *KInvalidateOpts) error {
	body := url.Values{}
	body.Add("client_id", client.ClientID)
	body.Add("client_secret", client.ClientSecret)
	if opts.Refresh != nil {
		body.Add("refresh_token", *opts.Refresh)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/%s", client.BaseURL, "protocol/openid-connect/logout"),
		strings.NewReader(body.Encode()),
	)
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", opts.Token))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	if res.StatusCode >= 400 {
		return fmt.Errorf("could not log out")
	}

	return nil
}
