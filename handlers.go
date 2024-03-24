package authorize

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"git.sr.ht/~mariusor/lw"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/auth"
	"github.com/go-ap/authorize/internal/assets"
	"github.com/go-ap/client"
	"github.com/go-ap/errors"
	"github.com/go-ap/filters"
	"github.com/go-ap/processing"
	"github.com/go-chi/chi/v5"
	"github.com/mariusor/render"
	"github.com/openshift/osin"
	"github.com/pborman/uuid"
)

type PasswordChanger interface {
	PasswordSet(vocab.Item, []byte) error
	PasswordCheck(vocab.Item, []byte) error
}

type account struct {
	username string
	pw       string
	actor    *vocab.Actor
}

type FullStorage interface {
	ClientSaver
	ClientLister
	osin.Storage
	processing.Store
	processing.KeyLoader
	PasswordChanger
}

type ClientSaver interface {
	// UpdateClient updates the client (identified by it's id) and replaces the values with the values of client.
	UpdateClient(c osin.Client) error
	// CreateClient stores the client in the database and returns an error, if something went wrong.
	CreateClient(c osin.Client) error
	// RemoveClient removes a client (identified by id) from the database. Returns an error if something went wrong.
	RemoveClient(id string) error
}

type ClientLister interface {
	// ListClients lists existing clients
	ListClients() ([]osin.Client, error)
	GetClient(id string) (osin.Client, error)
}

func (a account) IsLogged() bool {
	return a.actor != nil && a.actor.PreferredUsername.First().Value.String() == a.username
}

func (a *account) FromActor(p *vocab.Actor) {
	a.username = p.PreferredUsername.First().String()
	a.actor = p
}

type Service struct {
	Stores []FullStorage
	Client client.Basic
	Logger lw.Logger
}

// GenerateID creates an IRI that can be used to uniquely identify the "it" item, based on the collection "col" and
// its creator "by"
func (s Service) generateID(it vocab.Item, _ vocab.Item, by vocab.Item) (vocab.ID, error) {
	app, _, err := s.findMatchingStorage(iriBaseURL(it.GetLink()))
	if err != nil {
		return "", errors.NewNotFound(err, "not found")
	}
	base := app.GetLink().GetID()
	typ := it.GetType()

	var partOf vocab.IRI
	if vocab.ActivityTypes.Contains(typ) || vocab.IntransitiveActivityTypes.Contains(typ) {
		partOf = filters.ActivitiesType.IRI(base)
	} else if vocab.ActorTypes.Contains(typ) || typ == vocab.ActorType {
		partOf = filters.ActorsType.IRI(base)
	} else {
		partOf = filters.ObjectsType.IRI(base)
	}
	return generateID(it, partOf, by)
}

// GenerateID generates an unique identifier for the it ActivityPub Object.
func generateID(it vocab.Item, partOf vocab.IRI, by vocab.Item) (vocab.ID, error) {
	uuid := uuid.New()
	id := partOf.GetLink().AddPath(uuid)
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
				id = vocab.ID(fmt.Sprintf("%s/%s", outbox, uuid))
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
	return id, nil
}

const (
	meKey           = "me"
	redirectUriKey  = "redirect_uri"
	clientIdKey     = "client_id"
	responseTypeKey = "response_type"

	ID osin.AuthorizeRequestType = "id"
)

func (s Service) findMatchingStorage(hosts ...string) (vocab.Actor, FullStorage, error) {
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
	return app, nil, fmt.Errorf("unable to find storage")
}

func (s Service) server(req *http.Request) (*auth.Server, error) {
	app, db, err := s.findMatchingStorage(baseURL(req))
	if err != nil {
		return nil, errors.NewNotFound(err, "resource not found %s", req.Host)
	}
	if db == nil {
		return nil, errors.NotFoundf("resource not found %s", req.Host)
	}

	return auth.New(
		auth.WithURL(app.GetLink().String()),
		auth.WithStorage(db),
		auth.WithClient(s.Client),
		auth.WithLogger(s.Logger.WithContext(lw.Ctx{"log": "osin"})),
	)
}

func (s Service) IsValidRequest(r *http.Request) bool {
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

func IndieAuthClientActor(author vocab.Item, url *url.URL) *vocab.Actor {
	now := time.Now().UTC()
	preferredUsername := url.Host
	p := vocab.Person{
		Type:         vocab.ApplicationType,
		AttributedTo: author.GetLink(),
		Audience:     vocab.ItemCollection{vocab.PublicNS},
		Generator:    author.GetLink(),
		Published:    now,
		Summary: vocab.NaturalLanguageValues{
			{vocab.NilLangRef, vocab.Content("IndieAuth generated actor")},
		},
		Updated: now,
		PreferredUsername: vocab.NaturalLanguageValues{
			{vocab.NilLangRef, vocab.Content(preferredUsername)},
		},
		URL: vocab.IRI(url.String()),
	}

	return &p
}

func (s Service) ValidateClient(r *http.Request) (*vocab.Actor, error) {
	r.ParseForm()
	clientID, err := url.QueryUnescape(r.FormValue(clientIdKey))
	if err != nil {
		return nil, err
	}
	if clientID == "" {
		return nil, nil
	}
	clientURL, err := url.Parse(clientID)
	if err != nil {
		return nil, nil
	}

	unescapedUri, err := url.QueryUnescape(r.FormValue(redirectUriKey))
	if err != nil {
		return nil, err
	}

	// load the 'me' value of the actor that wants to authenticate
	me, err := url.QueryUnescape(r.FormValue(meKey))
	if err != nil {
		return nil, err
	}

	app, storage, err := s.findMatchingStorage(baseURL(r))
	if err != nil {
		return nil, err
	}
	baseIRI := app.GetLink()

	// check for existing user actor
	var actor vocab.Item
	if me != "" {
		iri := SearchActorsIRI(baseIRI, ByType(vocab.PersonType), ByURL(vocab.IRI(me)))
		actor, err = storage.Load(iri)
		if err != nil {
			return nil, err
		}
		if actor == nil {
			return nil, errors.NotFoundf("unknown actor")
		}
	}
	// check for existing application actor
	iri := SearchActorsIRI(baseIRI, ByType(vocab.ApplicationType), ByURL(vocab.IRI(clientID)))
	clientActor, err := storage.Load(iri, filters.SameURL(vocab.IRI(clientID)), filters.HasType(vocab.ApplicationType))
	if err != nil {
		return nil, err
	}
	if clientActor == nil {
		newClient := IndieAuthClientActor(actor, clientURL)
		if err != nil {
			return nil, err
		}
		if newId, err := s.generateID(newClient, vocab.Outbox.IRI(actor), nil); err == nil {
			newClient.ID = newId
		}
		clientActor, err = storage.Save(newClient)
		if err != nil {
			return nil, err
		}
	}
	id := path.Base(clientActor.GetID().String())
	// must have a valid client
	if _, err = storage.GetClient(id); err != nil {
		if errors.IsNotFound(err) {
			// create client
			newClient := osin.DefaultClient{
				Id:          id,
				Secret:      "",
				RedirectUri: unescapedUri,
				//UserData:    userData,
			}
			if err = storage.CreateClient(&newClient); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
		r.Form.Set(clientIdKey, id)
		if osin.AuthorizeRequestType(r.FormValue(responseTypeKey)) == ID {
			r.Form.Set(responseTypeKey, "code")
		}
		if act, ok := actor.(*vocab.Actor); ok {
			return act, nil
		}

	}
	return nil, nil
}

var scopeAnonymousUserCreate = "anonUserCreate"

func iriBaseURL(iri vocab.IRI) string {
	u, _ := iri.URL()
	u.Path = "/"
	u.RawQuery = ""
	u.RawFragment = ""
	return u.String()
}

func (s *Service) loadAccountByID(iri vocab.IRI) (*vocab.Actor, error) {
	_, storage, err := s.findMatchingStorage(iriBaseURL(iri))
	if err != nil {
		return nil, err
	}

	actors, err := storage.Load(iri)
	if err != nil {
		return nil, err
	}
	if actors == nil {
		return nil, errNotFound
	}
	if actors.IsCollection() {
		vocab.OnCollectionIntf(actors, func(col vocab.CollectionInterface) error {
			actors = col.Collection()
			return nil
		})
	}

	var actor *vocab.Actor
	err = vocab.OnActor(actors, func(act *vocab.Actor) error {
		actor = act
		return nil
	})
	if err != nil || actor == nil {
		return nil, errNotFound
	}
	return actor, nil
}

type secret string

func (s secret) String() string {
	if len(s) <= 3 {
		return "***"
	}
	if len(s) <= 5 {
		hidden := strings.Repeat("*", len(s)-2)
		return hidden + string(s[len(s)-2:])
	}
	hidden := strings.Repeat("*", len(s)-3)
	return string(s[0]) + hidden + string(s[len(s)-2:])
}

func (s *Service) loadAccountFromPost(r *http.Request) (*account, error) {
	pw := r.PostFormValue("pw")
	handle := r.PostFormValue("handle")

	//a := ap.Self(i.baseIRI)

	app, storage, err := s.findMatchingStorage(baseURL(r))
	if err != nil {
		return nil, err
	}
	baseIRI := app.GetLink()

	searchIRI := SearchActorsIRI(baseIRI, ByName(handle), ByType(vocab.PersonType))
	actors, err := storage.Load(searchIRI, filters.NameIs(handle), filters.HasType(vocab.PersonType))
	if err != nil {
		return nil, errUnauthorized
	}
	if actors.IsCollection() {
		vocab.OnCollectionIntf(actors, func(col vocab.CollectionInterface) error {
			actors = col.Collection()
			return nil
		})
	}

	var act *account
	var logger = s.Logger.WithContext(lw.Ctx{
		"handle": handle,
		"pass":   secret(pw),
	})
	if act, err = checkPw(actors, []byte(pw), storage); err != nil {
		logger.WithContext(lw.Ctx{"error": err.Error()}).Errorf("failed")
		return nil, err
	}

	logger.Infof("success")
	return act, nil
}

func reqUrl(r *http.Request) string {
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	return fmt.Sprintf("%s://%s%s", proto, r.Host, r.RequestURI)
}

func (s *Service) Authorize(w http.ResponseWriter, r *http.Request) {
	a, err := s.server(r)
	if err != nil {
		s.HandleError(errNotFound).ServeHTTP(w, r)
		return
	}

	resp := a.NewResponse()
	defer resp.Close()

	loader, ok := a.Storage.(processing.ReadStore)
	if !ok {
		s.HandleError(errors.Newf("invalid storage to load actor")).ServeHTTP(w, r)
		return
	}
	var actor vocab.Item = &auth.AnonymousActor
	if s.IsValidRequest(r) {
		if actor, err = s.ValidateClient(r); err != nil {
			resp.SetError(osin.E_INVALID_REQUEST, err.Error())
			s.redirectOrOutput(resp, w, r)
			return
		}
	}

	if c := chi.URLParam(r, "id"); c != "" {
		if actorUrl, err := url.ParseRequestURI(reqUrl(r)); err == nil {
			actorUrl.Path = actorUrl.Path[:strings.Index(actorUrl.Path, "/oauth")]
			actorUrl.RawQuery = ""
			actorUrl.Fragment = ""
			if it, err := loader.Load(vocab.IRI(actorUrl.String())); err == nil {
				actor = it
			}
		}
	}

	ltx := lw.Ctx{}
	var overrideRedir = false

	ar := a.HandleAuthorizeRequest(resp, r)
	if ar != nil {
		ltx["grant_type"] = ar.Type
		ltx["client"] = ar.Client.GetId()
		ltx["state"] = ar.State
		if r.Method == http.MethodGet {
			if ar.Scope == scopeAnonymousUserCreate {
				// FIXME(marius): this seems like a way to backdoor our selves, we need a better way
				ar.Authorized = true
				overrideRedir = true
				iri := ar.HttpRequest.URL.Query().Get("actor")
				ar.UserData = iri
			} else {
				// this is basically the login page, with client being set
				m := login{title: "Login"}
				m.account = actor

				// check for existing application actor
				clientIRI := filters.ActorsType.IRI(vocab.IRI(baseURL(r))).AddPath(ar.Client.GetId())
				if u, err := url.ParseRequestURI(ar.Client.GetId()); err == nil && u.Host != "" {
					clientIRI = vocab.IRI(ar.Client.GetId())
				}

				it, err := loader.Load(clientIRI)
				if err != nil {
					resp.SetError(osin.E_INVALID_REQUEST, fmt.Sprintf("invalid client: %+s", err))
					s.redirectOrOutput(resp, w, r)
					return
				}
				m.client = it
				m.state = ar.State

				s.renderTemplate(r, w, "login", m)
				return
			}
		} else {
			acc, err := s.loadAccountFromPost(r)
			if err != nil {
				resp.SetError(osin.E_ACCESS_DENIED, err.Error())
				s.Logger.WithContext(ltx).Errorf("Authorization failed")
			}
			if acc != nil {
				ar.Authorized = true
				ar.UserData = acc.actor.GetLink()
			}
			ltx["handle"] = nameOf(actor)
		}
	}
	a.FinishAuthorizeRequest(resp, r, ar)
	if overrideRedir {
		resp.Type = osin.DATA
	}
	ltx["return_url"] = resp.URL
	logFn := s.Logger.WithContext(ltx).Warnf
	if ar != nil {
		ltx["authorized"] = ar.Authorized
		ltx["state"] = ar.State
		if ar.Authorized {
			logFn = s.Logger.WithContext(ltx).Infof
		}
	}
	logFn("Token")
	s.redirectOrOutput(resp, w, r)
}

func checkPw(it vocab.Item, pw []byte, pwLoader PasswordChanger) (*account, error) {
	acc := new(account)
	found := false
	err := vocab.OnActor(it, func(p *vocab.Actor) error {
		if found {
			return nil
		}
		if err := pwLoader.PasswordCheck(p, pw); err == nil {
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

func ByName(names ...string) url.Values {
	q := make(url.Values)
	q["name"] = names
	return q
}

func ByType(types ...vocab.ActivityVocabularyType) url.Values {
	q := make(url.Values)
	tt := make([]string, len(types))
	for i, t := range types {
		tt[i] = string(t)
	}
	q["type"] = tt
	return q
}

func ByURL(urls ...vocab.IRI) url.Values {
	q := make(url.Values)
	uu := make([]string, len(urls))
	for i, u := range urls {
		uu[i] = u.String()
	}
	q["url"] = uu
	return q
}

func IRIWithFilters(iri vocab.IRI, searchParams ...url.Values) vocab.IRI {
	q := make(url.Values)
	for _, params := range searchParams {
		for k, vals := range params {
			if _, ok := q[k]; !ok {
				q[k] = make([]string, 0)
			}
			q[k] = append(q[k], vals...)
		}
	}
	if s, err := iri.URL(); err == nil {
		s.RawQuery = q.Encode()
		iri = vocab.IRI(s.String())
	}
	return iri
}

func SearchActorsIRI(baseIRI vocab.IRI, searchParams ...url.Values) vocab.IRI {
	return IRIWithFilters(filters.ActorsType.IRI(baseIRI), searchParams...)
}

var AnonymousAcct = account{
	username: "anonymous",
	actor:    &auth.AnonymousActor,
}

func (s *Service) Token(w http.ResponseWriter, r *http.Request) {
	a, err := s.server(r)
	if err != nil {
		s.HandleError(errNotFound).ServeHTTP(w, r)
		return
	}

	resp := a.NewResponse()
	defer resp.Close()

	app, storage, err := s.findMatchingStorage(baseURL(r))
	if err != nil {
		s.HandleError(errNotFound).ServeHTTP(w, r)
		return
	}
	baseIRI := app.GetLink()

	acc := &AnonymousAcct
	if ar := a.HandleAccessRequest(resp, r); ar != nil {
		var actorSearchIRI vocab.IRI
		var actorCtx lw.Ctx
		switch ar.Type {
		case osin.PASSWORD:
			if u, _ := url.ParseRequestURI(ar.Username); u != nil && u.Host != "" {
				// NOTE(marius): here we send the full actor IRI as a username to avoid handler collisions
				actorSearchIRI = vocab.IRI(ar.Username)
				actorCtx = lw.Ctx{
					"actor": ar.Username,
				}
			} else {
				actorSearchIRI = SearchActorsIRI(baseIRI, ByName(ar.Username))
				actorCtx = lw.Ctx{
					"handle": ar.Username,
					"actor":  actorSearchIRI,
				}
			}
		case osin.AUTHORIZATION_CODE:
			if iri, ok := ar.UserData.(string); ok {
				actorSearchIRI = vocab.IRI(iri)
			}
			actorCtx = lw.Ctx{
				"actor": actorSearchIRI,
			}
		}
		actor, err := storage.Load(actorSearchIRI)
		if err != nil {
			s.HandleError(errUnauthorized).ServeHTTP(w, r)
			return
		}
		if ar.Type == osin.PASSWORD {
			if actor.IsCollection() {
				err = vocab.OnCollectionIntf(actor, func(col vocab.CollectionInterface) error {
					// NOTE(marius): This is a stupid way of doing pw authentication, as it will produce collisions
					//  for users with the same handle/pw and it will login the first in the collection.
					for _, actor := range col.Collection() {
						acc, err = checkPw(actor, []byte(ar.Password), storage)
						if err == nil {
							return nil
						}
					}
					return errors.Newf("No actor matched the password")
				})
			} else {
				acc, err = checkPw(actor, []byte(ar.Password), storage)
			}
			actorCtx["handle"] = nameOf(actor)
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
		if ar.Type == osin.AUTHORIZATION_CODE {
			vocab.OnActor(actor, func(p *vocab.Actor) error {
				acc = new(account)
				acc.FromActor(p)
				ar.Authorized = acc.IsLogged()
				ar.UserData = acc.actor.GetLink()
				return nil
			})
		}
		a.FinishAccessRequest(resp, r, ar)
		s.Logger.WithContext(actorCtx, lw.Ctx{
			"authorized": ar.Authorized,
			"grant_type": ar.Type,
			"client":     ar.Client.GetId(),
			"code":       secret(ar.Code),
		}).Infof("Authorized")
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

type login struct {
	title   string
	account vocab.Item
	state   string
	client  vocab.Item
}

func (l login) Title() string {
	return l.title
}

func (l login) Account() vocab.Item {
	return l.account
}

func (l login) State() string {
	return l.state
}

func (l login) Client() vocab.Item {
	return l.client
}

func (l login) Handle() template.HTML {
	return nameOf(l.account)
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
		FileSystem:                assets.Templates,
		Directory:                 assets.TemplatesPath,
		Extensions:                []string{".html"},
		Funcs:                     []template.FuncMap{{"HTTPErrors": errors.HttpErrors}},
		Delims:                    render.Delims{Left: "{{", Right: "}}"},
		Charset:                   "UTF-8",
		DisableCharset:            false,
		HTMLContentType:           "text/html",
		DisableHTTPErrorRendering: false,
	}
	renderOptions = render.HTMLOptions{
		Funcs: template.FuncMap{
			"nameOf": nameOf,
			"iconOf": iconOf,
			"IsValid": func(it vocab.Item) bool {
				return !vocab.IsNil(it)
			},
		},
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
	var url string
	if vocab.IsIRI(icon) {
		url = icon.GetLink().String()
	} else {
		_ = vocab.OnObject(icon, func(ob *vocab.Object) error {
			url = ob.URL.GetLink().String()
			return nil
		})
	}
	if len(url) > 0 {
		return template.HTML(fmt.Sprintf(`<img src="%s" />`, url))
	}
	return ""
}

func nameOf(it vocab.Item) template.HTML {
	if vocab.IsNil(it) {
		return ""
	}
	name := unknownActorHandle
	if vocab.ActorTypes.Contains(it.GetType()) {
		_ = vocab.OnActor(it, func(act *vocab.Actor) error {
			if len(act.PreferredUsername) > 0 {
				name = act.PreferredUsername.First().String()
			}
			return nil
		})
	}
	if name == unknownActorHandle {
		_ = vocab.OnObject(it, func(ob *vocab.Object) error {
			if len(ob.Name) > 0 {
				name = ob.Name.First().String()
			}
			return nil
		})
	}
	return template.HTML(name)
}

func (s *Service) renderTemplate(r *http.Request, w http.ResponseWriter, name string, m authModel) {
	wrt := bytes.Buffer{}

	renderOptions.Funcs["redirectURI"] = func() string {
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
	err := ren.HTML(&wrt, http.StatusOK, name, m, renderOptions)
	if err == nil {
		io.Copy(w, &wrt)
		return
	}
	err = errors.Annotatef(err, "failed to render template")
	s.Logger.WithContext(lw.Ctx{"template": name, "model": fmt.Sprintf("%T", m)}).Errorf("%+s", err)
	status := errors.HttpStatus(err)
	if status == 0 {
		status = http.StatusInternalServerError
	}
	errRenderer.HTML(w, status, "error", err)
}

func (s *Service) HandleError(e error) http.HandlerFunc {
	s.Logger.Errorf("%+s", e)
	return func(w http.ResponseWriter, r *http.Request) {
		errRenderer.HTML(w, errors.HttpStatus(e), "error", e)
	}
}

func baseURL(r *http.Request) string {
	if r == nil {
		return ""
	}
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	path := "/"
	return fmt.Sprintf("%s://%s%s", proto, r.Host, path)
}

var (
	errUnauthorized = errors.Unauthorizedf("Invalid username or password")
	errNotFound     = errors.NotFoundf("actor not found")
)

type OAuth struct {
	Provider     string
	Code         string
	Token        string
	RefreshToken string
	TokenType    string
	Expiry       time.Time
	State        string
}

type pwChange struct {
	title   string
	account vocab.Item
}

func (p pwChange) Title() string {
	return p.title
}

func (p pwChange) Account() vocab.Item {
	return p.account
}

// ShowChangePw
func (s *Service) ShowChangePw(w http.ResponseWriter, r *http.Request) {
	actor := s.loadActorFromOauth2Session(w, r)
	if actor == nil {
		s.HandleError(errors.NotValidf("Unable to load actor from session")).ServeHTTP(w, r)
		return
	}

	app, _, err := s.findMatchingStorage(baseURL(r))
	if err != nil {
		s.HandleError(errNotFound).ServeHTTP(w, r)
		return
	}
	baseIRI := app.GetLink()

	if id := chi.URLParam(r, "id"); id != "" {
		act, err := s.loadAccountByID(filters.ActorsType.IRI(baseIRI).AddPath(id))
		if err != nil {
			s.HandleError(err).ServeHTTP(w, r)
			return
		}
		if !act.GetID().Equals(actor.GetID(), true) {
			s.HandleError(errors.NotValidf("Unable to load actor from session")).ServeHTTP(w, r)
			return
		}
	}

	m := pwChange{
		title:   "Change password",
		account: *actor,
	}

	s.renderTemplate(r, w, "password", m)
}

// HandleChangePw
func (s *Service) HandleChangePw(w http.ResponseWriter, r *http.Request) {
	actor := s.loadActorFromOauth2Session(w, r)
	if actor == nil {
		s.Logger.Errorf("Unable to load actor from session")
		s.HandleError(errors.NotValidf("Unable to load actor from session")).ServeHTTP(w, r)
		return
	}
	tok := r.URL.Query().Get("s")

	pw := r.PostFormValue("pw")
	pwConf := r.PostFormValue("pw-confirm")
	if pw != pwConf {
		s.HandleError(errors.Newf("Different passwords submitted")).ServeHTTP(w, r)
		return
	}

	_, storage, err := s.findMatchingStorage(baseURL(r))
	if err != nil {
		s.HandleError(errNotFound).ServeHTTP(w, r)
		return
	}

	if err = storage.PasswordSet(actor, []byte(pw)); err != nil {
		s.HandleError(errors.NotValidf("Unable to change password")).ServeHTTP(w, r)
		return
	}

	s.Logger.WithContext(lw.Ctx{
		"handle": actor.PreferredUsername.String(),
		"pass":   secret(pw),
	}).Infof("Changed pw")

	storage.RemoveAuthorize(tok)
}

func (s *Service) loadActorFromOauth2Session(w http.ResponseWriter, r *http.Request) *vocab.Actor {
	notF := errors.NotFoundf("Not found")
	// TODO(marius): we land on this handler, coming from an email link containing a token identifying the Actor
	tok := r.URL.Query().Get("s")
	if len(tok) == 0 {
		s.HandleError(notF).ServeHTTP(w, r)
		return nil
	}
	_, storage, err := s.findMatchingStorage(baseURL(r))
	if err != nil {
		s.HandleError(errNotFound).ServeHTTP(w, r)
		return nil
	}

	authSess, err := storage.LoadAuthorize(tok)
	if err != nil {
		s.HandleError(notF).ServeHTTP(w, r)
		return nil
	}
	if authSess == nil {
		s.HandleError(notF).ServeHTTP(w, r)
		return nil
	}
	if authSess.ExpireAt().Sub(time.Now().UTC()) < 0 {
		s.HandleError(notF).ServeHTTP(w, r)
		return nil
	}
	if authSess.UserData == nil {
		s.HandleError(notF).ServeHTTP(w, r)
		return nil
	}

	actorIRI, err := assertToBytes(authSess.UserData)
	if err != nil {
		s.HandleError(notF).ServeHTTP(w, r)
		return nil
	}
	ob, err := storage.Load(vocab.IRI(actorIRI))
	if err != nil || ob == nil {
		s.HandleError(notF).ServeHTTP(w, r)
		return nil
	}
	var actor *vocab.Actor
	vocab.OnActor(ob, func(p *vocab.Actor) error {
		actor = p
		return nil
	})
	return actor
}

func assertToBytes(in any) ([]byte, error) {
	var ok bool
	var data string
	if in == nil {
		return nil, nil
	} else if data, ok = in.(string); ok {
		return []byte(data), nil
	} else if byt, ok := in.([]byte); ok {
		return byt, nil
	} else if byt, ok := in.(json.RawMessage); ok {
		return byt, nil
	} else if str, ok := in.(fmt.Stringer); ok {
		return []byte(str.String()), nil
	}
	return nil, errors.Errorf(`Could not assert "%v" to string`, in)
}
