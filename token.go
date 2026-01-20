package authorize

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"

	"git.sr.ht/~mariusor/lw"
	"git.sr.ht/~mariusor/mask"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/auth"
	"github.com/go-ap/authorize/internal/assets"
	"github.com/go-ap/errors"
	"github.com/go-ap/filters"
	"github.com/mariusor/render"
	"github.com/openshift/osin"
	"github.com/pborman/uuid"
)

type PasswordChanger interface {
	PasswordSet(vocab.IRI, []byte) error
	PasswordCheck(vocab.IRI, []byte) error
}

type account struct {
	username string
	pw       string
	actor    *vocab.Actor
}

type FullStorage interface {
	Open() error
	ClientSaver
	ClientLister
	Storage
	PasswordChanger
	osin.Storage
}

type ClientSaver interface {
	// CreateClient stores the client in the database and returns an error, if something went wrong.
	CreateClient(c osin.Client) error
}

type ClientLister interface {
	GetClient(id string) (osin.Client, error)
}

type Storage interface {
	Load(vocab.IRI, ...filters.Check) (vocab.Item, error)
	Save(vocab.Item) (vocab.Item, error)
	Delete(vocab.Item) error
	Create(vocab.CollectionInterface) (vocab.CollectionInterface, error)
	AddTo(vocab.IRI, ...vocab.Item) error
	RemoveFrom(vocab.IRI, ...vocab.Item) error
}

func (a account) IsLogged() bool {
	return a.actor != nil && a.actor.PreferredUsername.First().String() == a.username
}

func (a *account) FromActor(p *vocab.Actor) {
	a.username = vocab.PreferredNameOf(p)
	a.actor = p
}

type Service struct {
	Stores []FullStorage
	Client auth.Client
	Logger lw.Logger
}

// GenerateID generates a unique identifier for the 'it' [vocab.Item].
func generateID(it vocab.Item, partOf vocab.IRI, by vocab.Item, uid uuid.UUID) (vocab.ID, error) {
	if uid == nil {
		uid = uuid.NewRandom()
	}
	id := partOf.GetLink().AddPath(uid.String())
	typ := it.GetType()
	if vocab.ActivityTypes.Contains(typ) || vocab.IntransitiveActivityTypes.Contains(typ) {
		err := vocab.OnIntransitiveActivity(it, func(a *vocab.IntransitiveActivity) error {
			if rec := a.Recipients(); rec.Contains(vocab.PublicNS) {
				return nil
			}
			if vocab.IsNil(by) {
				by = a.Actor
			}
			if !vocab.IsNil(by) {
				// if "it" is not a public activity, save it to its actor Outbox instead of the global activities collection
				outbox := vocab.Outbox.IRI(by)
				id = vocab.ID(fmt.Sprintf("%s/%s", outbox, uid))
			}
			return nil
		})
		if err != nil {
			return id, err
		}
		err = vocab.OnObject(it, func(a *vocab.Object) error {
			a.ID = id
			return nil
		})
		return id, err
	}
	if it.IsLink() {
		return id, vocab.OnLink(it, func(l *vocab.Link) error {
			l.ID = id
			return nil
		})
	}
	return id, vocab.OnObject(it, func(o *vocab.Object) error {
		o.ID = id
		return nil
	})
}

const (
	meKey           = "me"
	redirectUriKey  = "redirect_uri"
	clientIdKey     = "client_id"
	responseTypeKey = "response_type"

	ID osin.AuthorizeRequestType = "id"
)

func (s *Service) findMatchingStorage(hosts ...string) (vocab.Actor, FullStorage, error) {
	var app vocab.Actor
	for _, db := range s.Stores {
		for _, host := range hosts {
			res, err := db.Load(vocab.IRI(host))
			if err != nil {
				continue
			}
			err = vocab.OnActor(res, func(actor *vocab.Actor) error {
				app = *actor
				return nil
			})
			if err != nil {
				continue
			}
			if app.ID != "" {
				return app, db, nil
			}
		}
	}
	return app, nil, errStorageNotFound
}

func (s *Service) auth(app vocab.Actor, db FullStorage) (*auth.Server, error) {
	return auth.New(
		auth.WithURL(app.GetLink().String()),
		auth.WithStorage(db),
		auth.WithClient(s.Client),
		auth.WithLogger(s.Logger.WithContext(lw.Ctx{"log": "osin"})),
	)
}

func (s *Service) IsValidRequest(r *http.Request) bool {
	clientID, err := url.QueryUnescape(r.FormValue(clientIdKey))
	if err != nil {
		return false
	}
	clURL, err := url.ParseRequestURI(clientID)
	if err != nil || clURL.Host == "" || clURL.Scheme == "" {
		return false
	}
	return true
}

func iriBaseURL(iri vocab.IRI) string {
	u, _ := iri.URL()
	u.Path = "/"
	u.RawQuery = ""
	u.RawFragment = ""
	return u.String()
}

func checkPw(it vocab.Item, pw []byte, pwLoader PasswordChanger) (*account, error) {
	acc := new(account)
	found := false
	err := vocab.OnActor(it, func(p *vocab.Actor) error {
		if found {
			return nil
		}
		if err := pwLoader.PasswordCheck(p.ID, pw); err == nil {
			acc.FromActor(p)
			found = true
		}
		return nil
	})
	if !found {
		return nil, errUnauthorized
	}
	return acc, err
}

var AnonymousAcct = account{
	username: "anonymous",
	actor:    &auth.AnonymousActor,
}

func iriFromUserData(raw any) (vocab.IRI, error) {
	if iri, ok := raw.(vocab.IRI); ok {
		return iri, nil
	}
	if iri, ok := raw.(string); ok {
		return vocab.IRI(iri), nil
	}
	if iri, ok := raw.([]byte); ok {
		return vocab.IRI(iri), nil
	}
	return "", errors.Errorf("invalid user data of type %T: %s, unable to convert to IRI", raw, raw)
}

func (s *Service) Token(w http.ResponseWriter, r *http.Request) {
	app, repo, err := s.findMatchingStorage(baseURL(r)...)
	if err != nil {
		s.HandleError(err).ServeHTTP(w, r)
		return
	}
	baseIRI := app.GetLink()

	acc := &AnonymousAcct
	a, err := s.auth(app, repo)
	if err != nil {
		s.HandleError(err).ServeHTTP(w, r)
		return
	}
	client, err := url.QueryUnescape(r.FormValue(clientIdKey))
	if err != nil {
		s.HandleError(err).ServeHTTP(w, r)
		return
	}
	cl, err := repo.GetClient(client)
	if err != nil {
		s.HandleError(err).ServeHTTP(w, r)
		return
	}

	resp := a.NewResponse()
	a.Config.AllowClientSecretInParams = true
	if vocab.IRI(client).Contains(app.ID, false) && r.FormValue("client_secret") == "" {
		// NOTE(marius): client ID and current server are on the same host
		r.Form.Set("client_secret", cl.GetSecret())
	}

	if ar := a.HandleAccessRequest(resp, r); ar != nil {
		var actorSearchIRI vocab.IRI
		var actorCtx lw.Ctx
		authCtx := lw.Ctx{
			"grant_type": ar.Type,
			"client":     ar.Client.GetId(),
		}
		switch ar.Type {
		case osin.PASSWORD:
			if u, _ := url.ParseRequestURI(ar.Username); u != nil && u.Host != "" {
				// NOTE(marius): here we send the full actor IRI as a username to avoid handler collisions
				actorSearchIRI = vocab.IRI(ar.Username)
				actorCtx = lw.Ctx{
					"actor": ar.Username,
					"pass":  mask.S(ar.Password).String(),
				}
			} else {
				actorSearchIRI = SearchActorsIRI(baseIRI, ByName(ar.Username))
				actorCtx = lw.Ctx{
					"handle": ar.Username,
					"actor":  actorSearchIRI,
				}
			}
		case osin.AUTHORIZATION_CODE, osin.REFRESH_TOKEN:
			if actorSearchIRI, err = iriFromUserData(ar.UserData); err != nil {
				s.Logger.Errorf("%+s", err)
				s.HandleError(errNotFound).ServeHTTP(w, r)
				return
			}
			actorCtx = lw.Ctx{
				"actor": actorSearchIRI,
				"code":  mask.S(ar.Code).String(),
			}
		}
		actor, err := repo.Load(actorSearchIRI)
		if err != nil {
			s.Logger.Errorf("%+s", err)
			s.HandleError(errNotFound).ServeHTTP(w, r)
			return
		}
		if ar.Type == osin.PASSWORD {
			if actor.IsCollection() {
				err = vocab.OnCollectionIntf(actor, func(col vocab.CollectionInterface) error {
					// NOTE(marius): This is a stupid way of doing pw authentication, as it will produce collisions
					//  for users with the same handle/pw and it will login the first in the collection.
					for _, actor := range col.Collection() {
						acc, err = checkPw(actor, []byte(ar.Password), repo)
						if err == nil {
							return nil
						}
					}
					return errors.Newf("No actor matched the password")
				})
			} else {
				acc, err = checkPw(actor, []byte(ar.Password), repo)
			}
			actorCtx["handle"] = vocab.PreferredNameOf(actor)
			if err != nil || acc == nil {
				if err == nil {
					err = errUnauthorized
				}
				resp.SetError(osin.E_ACCESS_DENIED, err.Error())
				s.redirectOrOutput(resp, w, r)
				return
			}
			ar.Authorized = acc.IsLogged()
			ar.UserData = acc.actor.GetLink()
		}
		if ar.Type == osin.AUTHORIZATION_CODE || ar.Type == osin.REFRESH_TOKEN {
			_ = vocab.OnActor(actor, func(p *vocab.Actor) error {
				acc = new(account)
				acc.FromActor(p)
				ar.Authorized = acc.IsLogged()
				ar.UserData = acc.actor.GetLink()
				return nil
			})
		}
		a.FinishAccessRequest(resp, r, ar)
		authCtx["authorized"] = ar.Authorized
		authCtx["code"] = mask.S(ar.Code).String()
		s.Logger.WithContext(actorCtx, authCtx).Infof("Token")
	}

	s.redirectOrOutput(resp, w, r)
}

func annotatedRsError(status int, old error, msg string, args ...any) error {
	var err error
	switch status {
	case http.StatusForbidden:
		err = errors.NewForbidden(old, msg, args...)
	case http.StatusUnauthorized:
		err = errors.NewUnauthorized(old, msg, args...)
	case http.StatusInternalServerError:
		fallthrough
	default:
		err = errors.Annotatef(old, msg, args...)
	}

	return err
}

func (s *Service) redirectOrOutput(rs *osin.Response, w http.ResponseWriter, r *http.Request) {
	if rs.IsError {
		ltx := lw.Ctx{
			"status_code": rs.ErrorStatusCode,
		}
		if rs.InternalError != nil {
			ltx["err"] = fmt.Sprintf("%+v", rs.InternalError)
		}
		for k, vv := range rs.Output {
			ltx[k] = fmt.Sprintf("%+v", vv)
		}
		s.Logger.WithContext(ltx).Errorf(rs.ErrorId)
	} else {
		// Add headers
		for i, k := range rs.Headers {
			for _, v := range k {
				w.Header().Add(i, v)
			}
		}
	}

	if rs.Type == osin.REDIRECT {
		// Output redirect with parameters
		u, err := rs.GetRedirectUrl()
		if err != nil {
			err := annotatedRsError(http.StatusInternalServerError, err, "Error getting OAuth2 redirect URL")
			s.HandleError(err).ServeHTTP(w, r)
			return
		}
		http.Redirect(w, r, u, http.StatusFound)
		return
	}

	// set content type if the response doesn't already have one associated with it
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(rs.StatusCode)

	encoder := json.NewEncoder(w)
	if err := encoder.Encode(rs.Output); err != nil {
		s.HandleError(err).ServeHTTP(w, r)
		return
	}
}

type model interface {
	Title() string
}

type authModel interface {
	model
	Account() vocab.Item
}

var (
	defaultRenderOptions = render.Options{
		FileSystem: assets.Templates,
		Directory:  assets.TemplatesPath,
		Extensions: []string{".html"},
		Funcs: []template.FuncMap{
			{
				"HTTPErrors": errors.HttpErrors,
				"nameOf": func(it vocab.Item) template.HTML {
					if vocab.IsNil(it) {
						return ""
					}
					return template.HTML(vocab.PreferredNameOf(it))
				},
				"iconOf": iconOf,
				"IsValid": func(it vocab.Item) bool {
					return !vocab.IsNil(it)
				},
			},
		},
		Delims:                    render.Delims{Left: "{{", Right: "}}"},
		Charset:                   "UTF-8",
		DisableCharset:            false,
		HTMLContentType:           "text/html",
		DisableHTTPErrorRendering: false,
	}
	renderOptions = render.HTMLOptions{
		Funcs: template.FuncMap{},
	}
	errRenderer = render.New(defaultRenderOptions)
	ren         = render.New(defaultRenderOptions)

	unknownActorHandle = "Unknown"
)

func iconOf(it vocab.Item) template.HTML {
	if vocab.IsNil(it) {
		return ""
	}
	var icon vocab.Item
	_ = vocab.OnObject(it, func(ob *vocab.Object) error {
		if !vocab.IsNil(ob.Icon) {
			icon = ob.Icon
		}
		return nil
	})
	var u string
	if vocab.IsIRI(icon) {
		u = icon.GetLink().String()
	} else {
		_ = vocab.OnObject(icon, func(ob *vocab.Object) error {
			u = ob.URL.GetLink().String()
			return nil
		})
	}
	if len(u) > 0 {
		return template.HTML(fmt.Sprintf(`<img src="%s" />`, u))
	}
	return ""
}

func redirectUri(r *http.Request) func() string {
	return func() string {
		if r.URL == nil || r.URL.Query() == nil {
			return ""
		}
		q := make(url.Values)
		q.Set("error", osin.E_UNAUTHORIZED_CLIENT)
		q.Set("error_description", "user denied authorization request")
		u, _ := url.QueryUnescape(r.URL.Query().Get("redirect_uri"))
		u = fmt.Sprintf("%s?%s", u, q.Encode())
		return u
	}
}

func (s *Service) HandleError(e error) http.HandlerFunc {
	s.Logger.Errorf("%s", e)
	return func(w http.ResponseWriter, r *http.Request) {
		if errors.IsNotFound(e) {
			e = errNotFound
		}
		wrt := bytes.Buffer{}

		renderOptions.Funcs["redirectURI"] = redirectUri(r)
		status := errors.HttpStatus(e)
		if status == 0 {
			status = http.StatusInternalServerError
		}
		err := errRenderer.HTML(w, status, "error", e, renderOptions)
		if err == nil {
			_, _ = io.Copy(w, &wrt)
			return
		}
		err = errors.Annotatef(err, "failed to render template")
		s.Logger.WithContext(lw.Ctx{"template": "error", "model": fmt.Sprintf("%T", e)}).Errorf("%+s", err)
		status = errors.HttpStatus(err)
		if status == 0 {
			status = http.StatusInternalServerError
		}
		_ = errRenderer.HTML(w, status, "error", err, renderOptions)
	}
}

func baseURL(r *http.Request) []string {
	if r == nil {
		return nil
	}
	up := "/"

	// NOTE(marius): due to the fact that the Authorize server runs behind a proxy which handles the TLS termination,
	// we can't rely on the request's TLS property to determine the scheme for our URL,
	// so we generate two base URLs, one for each scheme.
	return []string{
		fmt.Sprintf("http://%s%s", r.Host, up),
		fmt.Sprintf("https://%s%s", r.Host, up),
	}
}

var (
	errUnauthorized    = errors.Unauthorizedf("Invalid username or password")
	errNotFound        = errors.NotFoundf("actor not found")
	errStorageNotFound = errors.NotFoundf("matching storage not found")
)

var InMaintenanceMode bool = false
var InDebugMode bool = false

func (s *Service) OutOfOrderMw(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if InMaintenanceMode {
			s.HandleError(errors.ServiceUnavailablef("temporarily out of order")).ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
