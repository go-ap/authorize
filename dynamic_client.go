package authorize

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"

	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/auth"
	"github.com/go-ap/errors"
	"github.com/go-ap/filters"
	"github.com/go-ap/processing"
	"github.com/openshift/osin"
	"github.com/pborman/uuid"
)

type MetadataStorage interface {
	LoadMetadata(vocab.IRI, any) error
	SaveMetadata(vocab.IRI, any) error
}

// GenerateID creates an IRI that can be used to uniquely identify the "it" item, based on the collection "col" and
// its creator "by"
func generateClientID(it vocab.Item, _ vocab.Item, by vocab.Item, uid uuid.UUID) (vocab.ID, error) {
	base := vocab.IRI(iriBaseURL(by.GetLink()))
	typ := it.GetType()

	var partOf vocab.IRI
	if vocab.ActivityTypes.Match(typ) || vocab.IntransitiveActivityTypes.Match(typ) {
		partOf = filters.ActivitiesType.IRI(base)
	} else if vocab.ActorTypes.Match(typ) || typ == vocab.ActorType {
		partOf = filters.ActorsType.IRI(base)
	} else {
		partOf = filters.ObjectsType.IRI(base)
	}
	return generateID(it, partOf, by, uid)
}

func GenerateBasicClientRegistrationRequest(clientID vocab.IRI, redirect []string) *ClientMetadata {
	u, _ := clientID.URL()
	basicClientInfo := ClientMetadata{
		ClientID: string(clientID),
		ClientRegistrationRequest: ClientRegistrationRequest{
			ClientName:   u.Host,
			ClientURI:    string(clientID),
			RedirectUris: redirect,
			SoftwareID:   uuid.NewRandom(),
		},
	}
	return &basicClientInfo
}

func GeneratedClientActor(author vocab.Item, clientRequest ClientRegistrationRequest) *vocab.Actor {
	now := time.Now().Truncate(time.Second).UTC()

	urls := make(vocab.ItemCollection, 0, 3)
	_ = urls.Append(vocab.IRI(clientRequest.ClientURI))
	for _, redir := range clientRequest.RedirectUris {
		_ = urls.Append(vocab.IRI(redir))
	}

	clientActor := vocab.Application{
		Type:              vocab.ApplicationType,
		Audience:          vocab.ItemCollection{vocab.PublicNS},
		Published:         now,
		Updated:           now,
		PreferredUsername: vocab.DefaultNaturalLanguage(clientRequest.ClientName),
		Summary:           vocab.DefaultNaturalLanguage("Generated actor"),
		URL:               urls,
	}
	if !vocab.IsNil(author) {
		clientActor.AttributedTo = author.GetLink()
		clientActor.Generator = author.GetLink()
	}
	if newId, err := generateClientID(clientActor, vocab.Outbox.IRI(author), author, clientRequest.SoftwareID); err == nil {
		clientActor.ID = newId
	}

	// TODO(marius): generate a template file for client actor content
	//   which shows the rest of the client request provided info (links to tos, policy, scopes, grant types etc).
	if clientRequest.LogoURI != "" {
		clientActor.Icon = vocab.IRI(clientRequest.LogoURI)
	}

	return &clientActor
}

type ActorLoader interface {
	Load(vocab.IRI, ...filters.Check) (vocab.Item, error)
}

type MetadataLoader interface {
	LoadMetadata(vocab.IRI, any) error
	SaveMetadata(vocab.IRI, any) error
}

func actorIRIFromDynamicClientReq(r *http.Request) vocab.IRI {
	return vocab.IRI("https://" + filepath.Join(r.Host, strings.Replace(r.RequestURI, "oauth/client", "", 1)))
}

type ClientRegistrationErrorCode string

const (
	// InvalidRedirectURI The value of one or more redirection URIs is invalid.
	InvalidRedirectURI ClientRegistrationErrorCode = "invalid_redirect_uri"
	// InvalidClientMetadata The value of one of the client metadata fields is invalid and the
	// server has rejected this request.  Note that an authorization
	// server MAY choose to substitute a valid value for any requested
	// parameter of a client's metadata.
	InvalidClientMetadata ClientRegistrationErrorCode = "invalid_client_metadata"
	// InvalidSoftwareStatement The software statement presented is invalid.
	InvalidSoftwareStatement ClientRegistrationErrorCode = "invalid_software_statement"
	// UnapprovedSoftwareStatement The software statement presented is not approved for use by this
	// authorization server.
	UnapprovedSoftwareStatement ClientRegistrationErrorCode = "unapproved_software_statement"
)

// ValidateClientRegistrationRequest
// When an OAuth 2.0 error condition occurs, such as the client
// presenting an invalid initial access token, the authorization server
// returns an error response appropriate to the OAuth 2.0 token type.
// When a registration error condition occurs, the authorization server
// returns an HTTP 400 status code (unless otherwise specified) with
// content type "application/json" consisting of a JSON object [RFC7159]
// describing the error in the response body.
// Two members are defined for inclusion in the JSON object:
func ValidateClientRegistrationRequest(req ClientRegistrationRequest) error {
	// TODO(marius): validate individual redirect URIs
	if len(req.RedirectUris) == 0 {
		return ClientRegistrationError{
			ErrorCode:        InvalidRedirectURI,
			ErrorDescription: "no redirect URIs were provided",
		}
	}
	return nil
}

type ClientRegistrationError struct {
	// ErrorCode  Single ASCII error code string.
	ErrorCode ClientRegistrationErrorCode `json:"error"`
	// ErrorDescription Human-readable ASCII text description of the error used for debugging.
	ErrorDescription string `json:"error_description"`
}

func (e ClientRegistrationError) Error() string {
	return string(e.ErrorCode) + ": " + e.ErrorDescription
}

func (s *Service) ClientRegistration(w http.ResponseWriter, r *http.Request) {
	actorIRI := actorIRIFromDynamicClientReq(r)
	self, st, err := s.findMatchingStorage(string(actorIRI))
	if err != nil {
		s.HandleError(errors.Newf("no storage found for iri %s", actorIRI)).ServeHTTP(w, r)
		return
	}
	if vocab.IsNil(self) || self.Equals(auth.AnonymousActor) {
		s.HandleError(errors.NotFoundf("not found")).ServeHTTP(w, r)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		s.HandleError(errors.NewNotValid(err, "unable to read request body")).ServeHTTP(w, r)
		return
	}

	regReq := ClientRegistrationRequest{}
	if err := json.Unmarshal(body, &regReq); err != nil {
		s.HandleError(errors.NewBadRequest(err, "invalid RFC7591 payload")).ServeHTTP(w, r)
		return
	}

	if err = ValidateClientRegistrationRequest(regReq); err != nil {
		s.HandleError(err).ServeHTTP(w, r)
		return
	}

	var id string

	name := regReq.ClientName
	urls := make(vocab.ItemCollection, 0)

	redirect := make([]string, 0, len(regReq.RedirectUris))
	for _, redirectUrl := range regReq.RedirectUris {
		u, err := url.ParseRequestURI(redirectUrl)
		if err != nil {
			continue
		}
		if cleanPath := path.Clean(u.Path); cleanPath != "." {
			u.Path = cleanPath
		}
		if name == "" {
			name = u.Host
		}
		curURL := u.String()

		u.Path = ""
		_ = urls.Append(vocab.IRI(u.String()), vocab.IRI(curURL))
		redirect = append(redirect, curURL)
	}
	if regReq.ClientURI != "" {
		urls = append(urls, vocab.IRI(regReq.ClientURI))
	}

	pw := []byte(rand.Text())

	var clientActor *vocab.Actor
	var d osin.Client
	var status int

	clientActor = GeneratedClientActor(self, regReq)
	clientActorID := clientActor.ID

	maybeExists, err := st.Load(clientActor.ID)
	if err == nil {
		clientActor, err = vocab.ToActor(maybeExists)
		if err != nil {
			s.HandleError(errors.Conflictf("existing item at IRI %s but is not an actor %s", clientActorID, maybeExists.GetType())).ServeHTTP(w, r)
			return
		}

		d, err = st.GetClient(string(clientActorID))
		if err != nil {
			s.HandleError(errors.Newf("unable to load existing OAuth2 client application")).ServeHTTP(w, r)
			return
		}
		status = http.StatusOK
	} else {
		clientActor, err = AddActor(st, clientActor, pw, self)
		if err != nil {
			s.HandleError(err).ServeHTTP(w, r)
			return
		}
		id = clientActor.GetID().String()
		if id == "" {
			s.HandleError(errors.Newf("invalid actor saved, id is null")).ServeHTTP(w, r)
			return
		}

		userData, _ := json.Marshal(regReq)
		if d, err = CreateOAuthClient(st, clientActor, redirect, pw, userData); err != nil {
			s.HandleError(errors.Newf("unable to save OAuth2 client application")).ServeHTTP(w, r)
			return
		}
		status = http.StatusCreated
	}

	resp := ClientRegistrationResponse{
		ClientID:     d.GetId(),
		ClientSecret: d.GetSecret(),
		IssuedAt:     clientActor.Published.Unix(),
		Expires:      0,
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
	s.Logger.Debugf("%s %s%s %d %s", r.Method, r.Host, r.RequestURI, http.StatusOK, http.StatusText(http.StatusOK))
}

func AddKeyToPerson(metaSaver MetadataStorage, typ string) func(act *vocab.Actor) error {
	// TODO(marius): add a way to pass if we should overwrite the keys
	//  for now we'll assume that if we're calling this, we want to do it
	overwriteKeys := true
	return func(act *vocab.Actor) error {
		if !vocab.ActorTypes.Match(act.Type) {
			return nil
		}

		m := new(auth.Metadata)
		_ = metaSaver.LoadMetadata(act.ID, m)
		var pubB, prvB pem.Block
		if m.PrivateKey == nil || overwriteKeys {
			pubB, prvB = GenerateRSAKeyPair()
			m.PrivateKey = pem.EncodeToMemory(&prvB)
			if err := metaSaver.SaveMetadata(act.ID, m); err != nil {
				return errors.Annotatef(err, "failed saving metadata for actor: %s", act.ID)
			}
		} else {
			pubB = publicKeyFrom(m.PrivateKey)
		}
		if len(pubB.Bytes) > 0 {
			act.PublicKey = vocab.PublicKey{
				ID:           vocab.IRI(fmt.Sprintf("%s#main", act.ID)),
				Owner:        act.ID,
				PublicKeyPem: string(pem.EncodeToMemory(&pubB)),
			}
		}
		return nil
	}
}

func GenerateRSAKeyPair() (pem.Block, pem.Block) {
	keyPrv, _ := rsa.GenerateKey(rand.Reader, 2048)

	keyPub := keyPrv.PublicKey
	pubEnc, err := x509.MarshalPKIXPublicKey(&keyPub)
	if err != nil {
		panic(err)
	}
	prvEnc, err := x509.MarshalPKCS8PrivateKey(keyPrv)
	if err != nil {
		panic(err)
	}
	p := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubEnc,
	}
	r := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: prvEnc,
	}
	return p, r
}

func publicKeyFrom(prvBytes []byte) pem.Block {
	prv, _ := pem.Decode(prvBytes)
	var pubKey crypto.PublicKey
	if key, _ := x509.ParseECPrivateKey(prvBytes); key != nil {
		pubKey = key.PublicKey
	}
	if key, _ := x509.ParsePKCS8PrivateKey(prv.Bytes); pubKey == nil && key != nil {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			pubKey = k.PublicKey
		case *ecdsa.PrivateKey:
			pubKey = k.PublicKey
		case ed25519.PrivateKey:
			pubKey = k.Public()
		}
	}
	pubEnc, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return pem.Block{}
	}
	return pem.Block{Type: "PUBLIC KEY", Bytes: pubEnc}
}

func AddKeyToItem(st FullStorage, it vocab.Item, typ string) error {
	if metaSaver, ok := st.(MetadataStorage); ok {
		if err := vocab.OnActor(it, AddKeyToPerson(metaSaver, typ)); err != nil {
			return errors.Annotatef(err, "failed to process actor: %s", it.GetID())
		}
	}
	if _, err := st.Save(it); err != nil {
		return errors.Annotatef(err, "failed to save actor: %s", it.GetID())
	}
	return nil
}

func AddActor(st FullStorage, p *vocab.Actor, pw []byte, author vocab.Actor) (*vocab.Actor, error) {
	if st == nil {
		return nil, errors.Errorf("invalid storage backend")
	}
	if author.Equals(auth.AnonymousActor) {
		return nil, errors.Errorf("invalid parent actor")
	}

	// NOTE(marius): check if we have an actor already
	if act, err := st.Load(p.ID); err == nil {
		// TODO(marius): do something with the password
		//  It's possible that the incoming pw doesn't match the locally saved one ?
		return vocab.ToActor(act)
	}

	// NOTE(marius): we don't allow the processing module to auto generate the ID for the Create,
	// but we set it manually to an outbox/{intRand} IRI.
	create := vocab.Activity{
		ID:        p.ID.AddPath(string(vocab.Outbox)).AddPath(rand.Text()),
		Type:      vocab.CreateType,
		To:        vocab.ItemCollection{vocab.PublicNS},
		Actor:     author,
		Published: p.Published,
		Object:    p,
	}
	if create.AttributedTo == nil {
		create.AttributedTo = author.GetLink()
	}
	if !create.CC.Contains(author.GetLink()) {
		_ = create.CC.Append(author.GetLink())
	}

	outbox := vocab.Outbox.Of(author)
	if vocab.IsNil(outbox) {
		return nil, errors.Newf("unable to find Actor's outbox: %s", author)
	}

	iriIsLocal := func(i vocab.IRI) bool {
		return true
	}
	ap := processing.New(processing.WithStorage(st), processing.WithLocalIRIChecker(iriIsLocal))
	if _, err := ap.ProcessClientActivity(create, author, outbox.GetLink()); err != nil {
		return nil, err
	}

	// NOTE(marius): to allow for CIMD clients, we need to accept passwordless client creation
	if pw == nil {
		return p, nil
	}
	return p, st.PasswordSet(p.GetLink(), pw)
}

type ClientRegistrationResponse struct {
	// ClientID REQUIRED. OAuth 2.0 client identifier string.  It SHOULD NOT be
	//	currently valid for any other registered client, though an
	//	authorization server MAY issue the same client identifier to
	//	multiple instances of a registered client at its discretion.
	ClientID string `json:"client_id"`

	// ClientSecret
	// OPTIONAL.  OAuth 2.0 client secret string.  If issued, this MUST
	// be unique for each "client_id" and SHOULD be unique for multiple
	// instances of a client using the same "client_id".  This value is
	// used by confidential clients to authenticate to the token
	// endpoint, as described in OAuth 2.0 [RFC6749], Section 2.3.1.
	ClientSecret string `json:"client_secret"`

	// IssuedAt OPTIONAL.  Time at which the client identifier was issued.  The
	// time is represented as the number of seconds from
	// 1970-01-01T00:00:00Z as measured in UTC until the date/time of
	// issuance.
	IssuedAt int64 `json:"client_id_issued_at"`

	// Expires REQUIRED if "client_secret" is issued.  Time at which the client
	// secret will expire or 0 if it will not expire.  The time is
	// represented as the number of seconds from 1970-01-01T00:00:00Z as
	// measured in UTC until the date/time of expiration.
	Expires int64 `json:"client_secret_expires_at"`
}

type ClientRegistrationRequest struct {
	// RedirectUris Array of redirection URI strings for use in redirect-based flows
	// such as the authorization code and implicit flows.  As required by
	// Section 2 of OAuth 2.0 [RFC6749], clients using flows with
	// redirection MUST register their redirection URI values.
	// Authorization servers that support dynamic registration for
	// redirect-based flows MUST implement support for this metadata
	// value.
	RedirectUris []string `json:"redirect_uris"`

	// ClientName
	// Human-readable string name of the client to be presented to the
	// end-user during authorization.  If omitted, the authorization
	// server MAY display the raw "client_id" value to the end-user
	// instead.  It is RECOMMENDED that clients always send this field.
	// The value of this field MAY be internationalized, as described in
	// Section 2.2.
	ClientName string `json:"client_name"`

	// TokenEndpointAuthMethod
	// String indicator of the requested authentication method for the
	// token endpoint.  Values defined by this specification are:
	// *  "none": The client is a public client as defined in OAuth 2.0,
	//    Section 2.1, and does not have a client secret.
	// *  "client_secret_post": The client uses the HTTP POST parameters
	//    as defined in OAuth 2.0, Section 2.3.1.
	// *  "client_secret_basic": The client uses HTTP Basic as defined in
	//    OAuth 2.0, Section 2.3.1.
	// Additional values can be defined via the IANA "OAuth Token
	// Endpoint Authentication Methods" registry established in
	// Section 4.2.  Absolute URIs can also be used as values for this
	// parameter without being registered.  If unspecified or omitted,
	// the default is "client_secret_basic", denoting the HTTP Basic
	// authentication scheme as specified in Section 2.3.1 of OAuth 2.0.
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`

	// GrantTypes
	// Array of OAuth 2.0 grant type strings that the client can use at
	// the token endpoint.  These grant types are defined as follows:
	// *  "authorization_code": The authorization code grant type defined
	//    in OAuth 2.0, Section 4.1.
	// *  "implicit": The implicit grant type defined in OAuth 2.0,
	//    Section 4.2.
	// *  "password": The resource owner password credentials grant type
	//    defined in OAuth 2.0, Section 4.3.
	// *  "client_credentials": The client credentials grant type defined
	//    in OAuth 2.0, Section 4.4.
	// *  "refresh_token": The refresh token grant type defined in OAuth
	//    2.0, Section 6.
	// *  "urn:ietf:params:oauth:grant-type:jwt-bearer": The JWT Bearer
	//    Token Grant Type defined in OAuth JWT Bearer Token Profiles
	//    [RFC7523].
	// *  "urn:ietf:params:oauth:grant-type:saml2-bearer": The SAML 2.0
	//    Bearer Assertion Grant defined in OAuth SAML 2 Bearer Token
	//    Profiles [RFC7522].
	// If the token endpoint is used in the grant type, the value of this
	// parameter MUST be the same as the value of the "grant_type"
	// parameter passed to the token endpoint defined in the grant type
	// definition.  Authorization servers MAY allow for other values as
	// defined in the grant type extension process described in OAuth
	// 2.0, Section 4.5.  If omitted, the default behavior is that the
	// client will use only the "authorization_code" Grant Type.
	GrantTypes []string `json:"grant_types"`

	// ResponseTypes
	// Array of the OAuth 2.0 response type strings that the client can
	// use at the authorization endpoint.  These response types are
	// defined as follows:
	// *  "code": The authorization code response type defined in OAuth
	//    2.0, Section 4.1.
	// *  "token": The implicit response type defined in OAuth 2.0,
	//    Section 4.2.
	//  If the authorization endpoint is used by the grant type, the value
	// of this parameter MUST be the same as the value of the
	// "response_type" parameter passed to the authorization endpoint
	// defined in the grant type definition.  Authorization servers MAY
	// allow for other values as defined in the grant type extension
	// process is described in OAuth 2.0, Section 4.5.  If omitted, the
	// default is that the client will use only the "code" response type.
	ResponseTypes []string `json:"response_types,omitempty"`

	// ClientURI
	// URL string of a web page providing information about the client.
	// If present, the server SHOULD display this URL to the end-user in
	// a clickable fashion.  It is RECOMMENDED that clients always send
	// this field.  The value of this field MUST point to a valid web
	// page.  The value of this field MAY be internationalized, as
	// described in Section 2.2.
	ClientURI string `json:"client_uri,omitempty"`

	// LogoURI
	// URL string that references a logo for the client.  If present, the
	// server SHOULD display this image to the end-user during approval.
	// The value of this field MUST point to a valid image file.  The
	// value of this field MAY be internationalized, as described in
	// Section 2.2.
	LogoURI string `json:"logo_uri,omitempty"`

	// Scope
	// String containing a space-separated list of scope values (as
	// described in Section 3.3 of OAuth 2.0 [RFC6749]) that the client
	// can use when requesting access tokens.  The semantics of values in
	// this list are service specific.  If omitted, an authorization
	// server MAY register a client with a default set of scopes.
	Scope string `json:"scope,omitempty"`

	// Contacts
	// Array of strings representing ways to contact people responsible
	// for this client, typically email addresses.  The authorization
	// server MAY make these contact addresses available to end-users for
	// support requests for the client.  See Section 6 for information on
	// Privacy Considerations.
	Contacts []string `json:"contacts,omitempty"`

	// TosURI
	// URL string that points to a human-readable terms of service
	// document for the client that describes a contractual relationship
	// between the end-user and the client that the end-user accepts when
	// authorizing the client.  The authorization server SHOULD display
	// this URL to the end-user if it is provided.  The value of this
	// field MUST point to a valid web page.  The value of this field MAY
	// be internationalized, as described in Section 2.2.
	TosURI string `json:"tos_uri,omitempty"`

	// PolicyURI
	// URL string that points to a human-readable privacy policy document
	// that describes how the deployment organization collects, uses,
	// retains, and discloses personal data.  The authorization server
	// SHOULD display this URL to the end-user if it is provided.  The
	// value of this field MUST point to a valid web page.  The value of
	// this field MAY be internationalized, as described in Section 2.2.
	PolicyURI string `json:"policy_uri,omitempty"`

	// JwksURI
	// URL string referencing the client's JSON Web Key (JWK) Set
	// [RFC7517] document, which contains the client's public keys.  The
	// value of this field MUST point to a valid JWK Set document.  These
	// keys can be used by higher-level protocols that use signing or
	// encryption.  For instance, these keys might be used by some
	// applications for validating signed requests made to the token
	// endpoint when using JWTs for client authentication [RFC7523].  Use
	// of this parameter is preferred over the "jwks" parameter, as it
	// allows for easier key rotation.  The "jwks_uri" and "jwks"
	// parameters MUST NOT both be present in the same request or
	// response.
	JwksURI string `json:"jwks_uri,omitempty"`

	// Jwks
	// Client's JSON Web Key Set [RFC7517] document value, which contains
	// the client's public keys.  The value of this field MUST be a JSON
	// object containing a valid JWK Set.  These keys can be used by
	// higher-level protocols that use signing or encryption.  This
	// parameter is intended to be used by clients that cannot use the
	// "jwks_uri" parameter, such as native clients that cannot host
	// public URLs.  The "jwks_uri" and "jwks" parameters MUST NOT both
	// be present in the same request or response.
	Jwks json.RawMessage `json:"jwks,omitempty"`

	// SoftwareID
	// A unique identifier string (e.g., a Universally Unique Identifier
	// (UUID)) assigned by the client developer or software publisher
	// used by registration endpoints to identify the client software to
	// be dynamically registered.  Unlike "client_id", which is issued by
	// the authorization server and SHOULD vary between instances, the
	// "software_id" SHOULD remain the same for all instances of the
	// client software.  The "software_id" SHOULD remain the same across
	SoftwareID uuid.UUID `json:"software_id,omitempty"`

	// SoftwareVersion is a version identifier string for the client software identified by
	// "software_id".  The value of the "software_version" SHOULD change
	// on any update to the client software identified by the same
	// "software_id".  The value of this field is intended to be compared
	// using string equality matching and no other comparison semantics
	// are defined by this specification.  The value of this field is
	// outside the scope of this specification, but it is not intended to
	// be human readable and is usually opaque to the client and
	// authorization server.  The definition of what constitutes an
	// update to client software that would trigger a change to this
	// value is specific to the software itself and is outside the scope
	// of this specification.
	SoftwareVersion string `json:"software_version,omitempty"`
}
