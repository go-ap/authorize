package authorize

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/client/debug"
	"github.com/go-ap/errors"
	"github.com/openshift/osin"
)

// https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-00.html

// ValidateOCIMDIdentifier
// Spec: https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-00.html#name-client-identifier
func ValidateOCIMDIdentifier(clientID vocab.IRI) error {
	u, err := clientID.URL()
	if err != nil {
		return errors.Annotatef(err, "invalid URL for client identifier")
	}
	if u.Scheme != "http" && !IsDev.Load() {
		return errors.Newf("client identifier is not https")
	}
	if u.Path == "" {
		return errors.Newf("client identifier has an empty path")
	}
	if filepath.Clean(u.Path) != u.Path {
		return errors.Newf("client identifier has an empty path")
	}
	if u.User != nil {
		return errors.Newf("client identifier has username component")
	}
	return nil
}

// ValidateClientMetadata
// https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-00.html#name-client-metadata
func ValidateClientMetadata(c ClientRegistrationRequest) error {
	if strings.Contains(c.TokenEndpointAuthMethod, "client_secret_post") {
		return errors.Newf("client_secret_post is not a valid token_endpoint_auth_method")
	}
	return nil
}

func FetchClientMetadata(clientID vocab.IRI) (*ClientRegistrationRequest, error) {
	var tr http.RoundTripper = &http.Transport{}
	if IsDev.Load() {
		tr = debug.New(debug.WithTransport(tr), debug.WithPath(os.TempDir()))
	}

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID.String(), nil)
	if err != nil {
		return nil, err
	}

	// TODO(marius): Accept mime-type for Client Metadata Document is application/json
	// https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-00.html#section-4.1-3

	cl := DefaultClient.Load()
	res, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	c := ClientRegistrationRequest{}
	if err := json.NewDecoder(res.Body).Decode(&c); err != nil {
		return nil, err
	}

	if err := ValidateClientMetadata(c); err != nil {
		return nil, err
	}
	return &c, nil
}

func CreateOAuthClient(st FullStorage, clientActor *vocab.Actor, redirect []string, pw, userData []byte) error {
	id := string(clientActor.GetID())
	if id == "" {
		return errors.Newf("invalid actor saved, id is null")
	}

	if err := AddKeyToItem(st, clientActor, "RSA"); err != nil {
		return errors.Annotatef(err, "Error saving metadata for application %s", vocab.NameOf(clientActor))
	}

	d := &osin.DefaultClient{
		Id:          id,
		Secret:      string(pw),
		RedirectUri: strings.Join(redirect, "\n"),
		UserData:    userData,
	}

	if err := st.CreateClient(d); err != nil {
		return errors.Annotatef(err, "unable to save OAuth2 client application")
	}
	return nil
}
