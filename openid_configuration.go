package jwt_middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type OpenIDConfiguration struct {
	JWKSURI string   `json:"jwks_uri"`
}

func FetchOpenIDConfiguration(url string) (*OpenIDConfiguration, error) {
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
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