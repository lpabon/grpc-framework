/*
Copyright 2022 Portworx

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package auth

import (
	"context"
	"fmt"
)

type multiAuthenticatorImpl struct {
	authenticators map[string][]Authenticator
}

func NewMultiAuthenticatorDefault() (MultiAuthenticatorWithClientID, error) {
	authenticators := make(map[string][]Authenticator)
	return NewMultiAuthenticator(authenticators)
}

// NewMultiAuthenticator maintains a list of authenticators for a given issuer.
// The input argument is a map of issuers to a list of authenticators for that issuer.
// NOTE: This interface does not check if there are duplicate authenticators. The interface
// will own the input map and will not create a copy of it.
func NewMultiAuthenticator(
	authenticators map[string][]Authenticator,
) (MultiAuthenticatorWithClientID, error) {
	for issuer, authenticatorsList := range authenticators {
		if len(authenticatorsList) == 0 {
			return nil, fmt.Errorf("empty authenticators list for issuer %v", issuer)
		}
	}
	return &multiAuthenticatorImpl{
		authenticators: authenticators,
	}, nil
}

func (m *multiAuthenticatorImpl) GetAuthenticators(issuer string) []Authenticator {
	return m.authenticators[issuer]
}

func (m *multiAuthenticatorImpl) AddAuthenticator(issuer string, authenticator Authenticator) {
	if val, ok := m.authenticators[issuer]; !ok || val == nil {
		m.authenticators[issuer] = make([]Authenticator, 1)
	}
	m.authenticators[issuer] = append(m.authenticators[issuer], authenticator)
}

func (m *multiAuthenticatorImpl) ListIssuers() []string {
	var issuers []string
	for issuer, _ := range m.authenticators {
		issuers = append(issuers, issuer)
	}
	return issuers
}

func (m *multiAuthenticatorImpl) AuthenticateToken(ctx context.Context, idToken string) (*Claims, error) {
	tokenClaims, err := TokenClaims(idToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get claims from token: %w", err)
	}

	for _, authenticator := range m.GetAuthenticators(tokenClaims.Issuer) {
		claims, err := authenticator.AuthenticateToken(ctx, idToken)
		if err == nil {
			return claims, nil
		}
	}

	return nil, fmt.Errorf("failed to authenticate token for issuer %v and audience %v",
		tokenClaims.Issuer, tokenClaims.Audience)
}

func (m *multiAuthenticatorImpl) Username(claims *Claims) string {
	var username string
	// TODO: This code does not handle the case where there are multiple authenticators
	// registered with the same issuer but different UsernameClaimTypes.
	for _, authenticator := range m.GetAuthenticators(claims.Issuer) {
		if username = authenticator.Username(claims); username != "" {
			return username
		}
	}
	return username
}
