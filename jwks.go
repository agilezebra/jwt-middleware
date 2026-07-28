// This file contains code taken from github.com/team-carepay/traefik-jwt-plugin
// We would like to simply use github.com/go-jose/go-jose/v3 for the JWKS instead but traefik's yaegi interpreter messes up the unmarshalling.
package jwt_middleware

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
)

// JSONWebKey is a JSON web key returned by the JWKS request.
type JSONWebKey struct {
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	Alg string   `json:"alg"`
	Use string   `json:"use"`
	X5c []string `json:"x5c"`
	X5t string   `json:"x5t"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	K   string   `json:"k,omitempty"`
	X   string   `json:"x,omitempty"`
	Y   string   `json:"y,omitempty"`
	D   string   `json:"d,omitempty"`
	P   string   `json:"p,omitempty"`
	Q   string   `json:"q,omitempty"`
	Dp  string   `json:"dp,omitempty"`
	Dq  string   `json:"dq,omitempty"`
	Qi  string   `json:"qi,omitempty"`
	Crv string   `json:"crv,omitempty"`
}

// JSONWebKeySet represents a set of JSON web keys.
type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

// FetchJWKS loads JSON web keys from the given source and returns a map kid -> key.
func FetchJWKS(source string, client *http.Client) (map[string]any, error) {
	var decoder *json.Decoder
	description := source
	if isInlineJWKS(source) {
		decoder = json.NewDecoder(strings.NewReader(source))
		description = "inline JWKS"
	} else {
		response, err := client.Get(source)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close() //nolint:errcheck
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("got %d from %s", response.StatusCode, source)
		}
		decoder = json.NewDecoder(response.Body)
	}

	var jwks JSONWebKeySet
	err := decoder.Decode(&jwks)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", description, err)
	}
	keys := make(map[string]any, len(jwks.Keys))
	for _, jwk := range jwks.Keys {
		if jwk.Kid == "" {
			jwk.Kid = JWKThumbprint(jwk)
		}
		switch jwk.Kty {
		case "RSA":
			{
				nBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(jwk.N, "="))
				if err != nil {
					log.Printf("error decoding N: %v for kid: %v", err, jwk.Kid)
					break
				}
				eBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(jwk.E, "="))
				if err != nil {
					log.Printf("error decoding E: %v for kid: %v", err, jwk.Kid)
					break
				}
				keys[jwk.Kid] = &rsa.PublicKey{
					N: new(big.Int).SetBytes(nBytes),
					E: int(new(big.Int).SetBytes(eBytes).Uint64()),
				}
			}
		case "EC":
			{
				var curve elliptic.Curve
				switch jwk.Crv {
				case "P-256":
					curve = elliptic.P256()
				case "P-384":
					curve = elliptic.P384()
				case "P-521":
					curve = elliptic.P521()
				default:
					switch jwk.Alg {
					case "ES256":
						curve = elliptic.P256()
					case "ES384":
						curve = elliptic.P384()
					case "ES512":
						curve = elliptic.P521()
					default:
						curve = elliptic.P256()
					}
				}
				xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
				if err != nil {
					break
				}
				yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
				if err != nil {
					break
				}
				keys[jwk.Kid] = &ecdsa.PublicKey{
					Curve: curve,
					X:     new(big.Int).SetBytes(xBytes),
					Y:     new(big.Int).SetBytes(yBytes),
				}
			}
		case "OKP":
			{
				if jwk.Crv != "Ed25519" {
					log.Printf("unsupported OKP curve: %v for kid: %v", jwk.Crv, jwk.Kid)
					break
				}
				xBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(jwk.X, "="))
				if err != nil {
					log.Printf("error decoding X: %v for kid: %v", err, jwk.Kid)
					break
				}
				if len(xBytes) != ed25519.PublicKeySize {
					log.Printf("invalid Ed25519 key length %d for kid: %v", len(xBytes), jwk.Kid)
					break
				}
				keys[jwk.Kid] = ed25519.PublicKey(xBytes)
			}
		}
	}

	return keys, nil
}

// JWKThumbprint creates a JWK thumbprint out of pub
// as specified in https://tools.ietf.org/html/rfc7638.
func JWKThumbprint(jwk JSONWebKey) string {
	var text string
	switch jwk.Kty {
	case "RSA":
		text = fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, jwk.E, jwk.N)
	case "EC":
		text = fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, jwk.X, jwk.Y)
	case "OKP":
		text = fmt.Sprintf(`{"crv":"%s","kty":"OKP","x":"%s"}`, jwk.Crv, jwk.X)
	}
	bytes := sha256.Sum256([]byte(text))
	return base64.RawURLEncoding.EncodeToString(bytes[:])
}
