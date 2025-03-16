package jwt_middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type OpenIDConfiguration struct {
	JWKSURI string `json:"jwks_uri"`
}

// FetchOpenIDConfiguration fetches the OpenID configuration from the given URL.
func FetchOpenIDConfiguration(url string, client *http.Client) (*OpenIDConfiguration, error) {
	response, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got %d from %s", response.StatusCode, url)
	}
	var config OpenIDConfiguration
	err = json.NewDecoder(response.Body).Decode(&config)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}

	return &config, nil
}
