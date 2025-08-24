package keygloak

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
)

type KUserError struct {
	Message string `json:"errorMessage"`
}

type KUserCredential struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"`
}

type KUserOpts struct {
	Email     string `json:"email"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type KUser struct {
	ID          string            `json:"id"`
	Enabled     bool              `json:"enabled"`
	Email       string            `json:"email"`
	Username    string            `json:"username"`
	FirstName   string            `json:"firstName"`
	LastName    string            `json:"lastName"`
	Credentials []KUserCredential `json:"credentials"`
}

// Creates a new user inside the realm your set in your instance config.
//
// Client has to be previously authenticated using the Authenticate() method
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
		Credentials: []KUserCredential{
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
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", client.ClientToken.Access))
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
	Totp     string
}

// Retrieves a token for the user with the provided username, password and optional totp
func (client *KClient) SignInWithPassword(opts *KSignInOpts) (*KToken, error) {
	token, err := client.GetOpenIDToken(
		KGrantTypePassword,
		&KTokenOpts{
			Username: opts.Username,
			Password: opts.Password,
			Totp:     opts.Totp,
		},
	)
	if err != nil {
		return nil, err
	}

	return token, nil
}

type KUserInfo struct {
	ID            string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Username      string `json:"preferred_username"`
	FullName      string `json:"name"`
	FirstName     string `json:"given_name"`
	LastName      string `json:"family_name"`
}

// Retrieves user's info using the provided token
func (client *KClient) UserInfo(token string) (*KUserInfo, bool) {
	req, err := http.NewRequest(
		http.MethodGet,
		fmt.Sprintf("%s/%s", client.BaseURL, "protocol/openid-connect/userinfo"),
		nil,
	)
	if err != nil {
		return nil, false
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
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

	var response KUserInfo
	json.Unmarshal(data, &response)

	return &response, true
}
