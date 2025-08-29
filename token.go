package keygloak

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type KGrantType string

const (
	KGrantTypeAuthCode KGrantType = "authorization_code"
	KGrantTypeClient   KGrantType = "client_credentials"
	KGrantTypePassword KGrantType = "password"
	KGrantTypeRefresh  KGrantType = "refresh_token"
)

func (t KGrantType) string() string {
	return string(t)
}

type KToken struct {
	Type    string `json:"token_type"`
	Access  string `json:"access_token"`
	Refresh *string `json:"refresh_token"`
	Scope   string `json:"scope"`
}

type KTokenError struct {
	Message string `json:"error_description"`
}

type KTokenOpts struct {
	ClientID     string
	ClientSecret string
	Scope        string
	RefreshToken *string
	Username     *string
	Password     *string
	Totp         *string
}

// Retrieves a new JWT token from Keycloak using KTokenOptions
//
// Avoid using this method directly
func (client *KClient) GetOpenIDToken(grantType KGrantType, opts *KTokenOpts) (*KToken, error) {
	scope := cmp.Or(opts.Scope, "openid profile email")
	clientId := cmp.Or(opts.ClientID, client.ClientID)
	clientSecret := cmp.Or(opts.ClientSecret, client.ClientSecret)

	body := url.Values{}
	body.Add("grant_type", grantType.string())
	body.Add("client_id", clientId)
	body.Add("client_secret", clientSecret)
	body.Add("scope", scope)

	if grantType == KGrantTypeRefresh && opts.RefreshToken != nil {
		body.Add("refresh_token", *opts.RefreshToken)
	}
	if grantType == KGrantTypePassword {
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

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode >= 400 {
		var tokenError KTokenError
		json.Unmarshal(data, &tokenError)
		return nil, fmt.Errorf("could not retrieve token: %s", tokenError.Message)
	}

	var token KToken
	json.Unmarshal(data, &token)

	return &token, nil
}

type KIntrospectionResponse struct {
	Active    bool   `json:"active"`
	TokenType string `json:"token_type"`
	Scope     string `json:"scope"`
	Email     string `json:"email"`
	Username  string `json:"username"`
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

// Validates the given accessToken and tries to refresh it if invalid
func (client *KClient) RefreshToken(accessToken string, refreshToken string) (*KToken, error) {
	result, ok := client.IntrospectToken(accessToken)
	if !ok {
		token, err := client.GetOpenIDToken(KGrantTypeRefresh, &KTokenOpts{RefreshToken: &refreshToken})
		if err != nil {
			return nil, err
		}

		return token, nil
	}

	return &KToken{
		Type:    result.TokenType,
		Access:  accessToken,
		Refresh: &refreshToken,
		Scope:   result.Scope,
	}, nil
}

// Invalidates the token session
func (client *KClient) InvalidateToken(refreshToken string) error {
	body := url.Values{}
	body.Add("client_id", client.ClientID)
	body.Add("client_secret", client.ClientSecret)
	body.Add("refresh_token", refreshToken)

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/%s", client.BaseURL, "protocol/openid-connect/logout"),
		strings.NewReader(body.Encode()),
	)
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	if res.StatusCode >= 400 {
		data, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		var tokenError KTokenError
		json.Unmarshal(data, &tokenError)
		return fmt.Errorf("could not invalidate token: %s", tokenError.Message)
	}

	return nil
}
