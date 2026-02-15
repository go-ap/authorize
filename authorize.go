package authorize

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"git.sr.ht/~mariusor/lw"
	"git.sr.ht/~mariusor/mask"
	"git.sr.ht/~mariusor/storage-all"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/auth"
	"github.com/go-ap/errors"
	"github.com/go-ap/filters"
	"github.com/go-chi/chi/v5"
	"github.com/openshift/osin"
)

func (s *Service) authFromRequest(req *http.Request) (*auth.Server, error) {
	app, db, err := s.findMatchingStorage(baseURL(req)...)
	if err != nil {
		return nil, errors.NewNotFound(err, "resource not found %s", req.Host)
	}
	if db == nil {
		return nil, errors.NotFoundf("resource not found %s", req.Host)
	}

	return s.auth(app, db)
}

func LoadClientActorByID(repo FullStorage, app vocab.Actor, clientID vocab.IRI) (*vocab.Actor, error) {
	// check for existing application actor
	clientActorItem, err := repo.Load(clientID)
	if err != nil && errors.IsNotFound(err) {
		// NOTE(marius): fallback to searching for the OAuth2 application by URL
		actorCol, err := repo.Load(vocab.Outbox.IRI(app), filters.HasType(vocab.CreateType), filters.Object(filters.SameURL(clientID), filters.HasType(vocab.ApplicationType)))
		if err != nil && !errors.IsNotFound(err) {
			return nil, err
		}
		err = vocab.OnCollectionIntf(actorCol, func(col vocab.CollectionInterface) error {
			for _, it := range col.Collection() {
				_ = vocab.OnActivity(it, func(act *vocab.Activity) error {
					clientActorItem = act.Object
					return nil
				})
				if !vocab.IsNil(clientActorItem) {
					break
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return vocab.ToActor(clientActorItem)
}

func (s *Service) ValidateOrCreateClient(r *http.Request) (*vocab.Actor, error) {
	// NOTE(marius): we should try to use Evan's diagram:
	// https://github.com/swicg/activitypub-api/issues/1#issuecomment-3708524521
	_ = r.ParseForm()
	client, err := url.QueryUnescape(r.FormValue(clientIdKey))
	if err != nil {
		return nil, err
	}
	if client == "" {
		return nil, nil
	}
	clientID := vocab.IRI(client)

	app, repo, err := s.findMatchingStorage(baseURL(r)...)
	if err != nil {
		return nil, err
	}
	baseIRI := app.GetLink()

	author := app
	// check for existing user actor
	// load the 'me' value of the actor that wants to authenticate
	me, _ := url.QueryUnescape(r.FormValue(meKey))
	if me != "" {
		// NOTE(marius): this is an indie auth request
		iri := SearchActorsIRI(baseIRI, ByType(vocab.PersonType), ByURL(vocab.IRI(me)))
		actorCol, err := repo.Load(iri)
		if err != nil {
			return nil, err
		}
		err = vocab.OnCollectionIntf(actorCol, func(col vocab.CollectionInterface) error {
			maybeActor, err := vocab.ToActor(col.Collection().First())
			if err != nil {
				return err
			}
			author = *maybeActor
			return nil
		})
		if err != nil {
			return nil, errors.NotFoundf("unknown actor")
		}
	}

	// check for existing application actor
	clientActor, err := LoadClientActorByID(repo, app, clientID)
	if err != nil && errors.IsNotFound(err) {
		if err != nil {
			return nil, err
		}
	}

	var userData []byte
	var redirect []string

	unescapedUri, err := url.QueryUnescape(r.FormValue(redirectUriKey))
	if err != nil {
		return nil, err
	}
	if len(unescapedUri) > 0 {
		redirect = append(redirect, unescapedUri)
	}

	if vocab.IsNil(clientActor) {
		// NOTE(marius): if we were unable to find any local client matching ClientID,
		// we attempt a OAuth Client ID Metadata Document based client registration mechanism.
		res, err := FetchClientMetadata(clientID)
		if err != nil {
			// NOTE(marius): if OCIMD registration failed, we try an IndieAuth client
			// TODO(marius): fix IndieAuth automatic client creation
			//  See https://todo.sr.ht/~mariusor/go-activitypub/34
			res = GenerateBasicClientRegistrationRequest(clientID, redirect)
		}

		redirect = res.RedirectUris
		userData, _ = json.Marshal(res)
		newClient := GeneratedClientActor(author, res.ClientRegistrationRequest, clientID)

		clientActor, err = AddActor(repo, newClient, nil, author)
		if err != nil {
			return nil, err
		}
		if vocab.IsNil(clientActor) {
			return nil, errors.Newf("unable to generate OAuth2 client")
		}
	}

	// must have a valid client
	id := string(clientActor.ID)
	if _, err = repo.GetClient(id); err != nil {
		if errors.IsNotFound(err) {
			if _, err = CreateOAuthClient(repo, clientActor, redirect, nil, userData); err != nil {
				return nil, errors.Newf("unable to save OAuth2 client")
			}
		} else {
			return nil, err
		}
	}

	r.Form.Set(clientIdKey, id)
	// TODO(marius): evaluate if this element is needed for the IndieAuth exchange or it just breaks things
	//if osin.AuthorizeRequestType(r.FormValue(responseTypeKey)) == ID {
	//	r.Form.Set(responseTypeKey, "code")
	//}

	return clientActor, nil
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

var scopeAnonymousUserCreate = "anonUserCreate"

func (s *Service) Authorize(w http.ResponseWriter, r *http.Request) {
	a, err := s.authFromRequest(r)
	if err != nil {
		s.HandleError(err).ServeHTTP(w, r)
		return
	}

	resp := a.NewResponse()

	loader, ok := a.Storage.(storage.ReadStore)
	if !ok {
		s.HandleError(errors.Newf("invalid storage to load actor")).ServeHTTP(w, r)
		return
	}

	if IsValidRequest(r) {
		clientActor, err := s.ValidateOrCreateClient(r)
		if err != nil {
			resp.SetError(osin.E_INVALID_REQUEST, err.Error())
			s.redirectOrOutput(resp, w, r)
			return
		}
		s.Logger.WithContext(lw.Ctx{"client": clientActor.ID}).Debugf("valid client")
	}

	var actor vocab.Item = &auth.AnonymousActor
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
	if ar == nil {
		s.redirectOrOutput(resp, w, r)
		return
	}

	ltx["grant_type"] = ar.Type
	ltx["client"] = ar.Client.GetId()
	ltx["state"] = ar.State
	if r.Method == http.MethodGet {
		if ar.Scope == scopeAnonymousUserCreate {
			// FIXME(marius): this is used by brutalinks to create users directly.
			//  It can probably be removed because the brutalinks client should be able to create actors using
			//  regular ActivityPub methods. The only thing remaining would be to set the password.
			ar.Authorized = true
			overrideRedir = true
			iri := ar.HttpRequest.URL.Query().Get("actor")
			ar.UserData = iri
		} else {
			// this is basically the login page, with client being set
			m := login{title: "Login"}
			m.account = actor

			var it vocab.Item
			// check for existing application actor
			for _, baseIRI := range baseURL(r) {
				// NOTE(marius): try to load based on client.ID as an IRI:
				it, _ = loader.Load(vocab.IRI(ar.Client.GetId()))
				if !vocab.IsNil(it) {
					m.client = it
					m.state = ar.State
					break
				} else {
					// NOTE(marius): try to load based on appending the client.ID to the actors collection:
					clientIRI := filters.ActorsType.IRI(vocab.IRI(baseIRI)).AddPath(filepath.Base(ar.Client.GetId()))
					if u, err := url.ParseRequestURI(ar.Client.GetId()); err == nil && u.Host != "" {
						clientIRI = vocab.IRI(ar.Client.GetId())
					}

					it, _ = loader.Load(clientIRI)
					if !vocab.IsNil(it) {
						m.client = it
						m.state = ar.State
						break
					}
				}
			}
			if vocab.IsNil(it) {
				resp.SetError(osin.E_INVALID_REQUEST, fmt.Sprintf("invalid client: %v", ar.Client))
				s.redirectOrOutput(resp, w, r)
				return
			}

			s.renderTemplate(r, w, "login", m)
			return
		}
	} else {
		handle := r.PostFormValue("handle")
		if vocab.IsNil(actor) {
			if acc, err := s.loadAccountFromPost(r); err == nil {
				actor = acc.actor
			}
		}
		if vocab.IsNil(actor) || vocab.PreferredNameOf(actor) != handle {
			resp.SetError(osin.E_ACCESS_DENIED, "authorization failed")
			s.Logger.WithContext(ltx).Errorf("Authorization failed")
		} else {
			ar.Authorized = true
			ar.UserData = actor.GetLink()
			ltx["handle"] = vocab.PreferredNameOf(actor)
		}
	}

	a.FinishAuthorizeRequest(resp, r, ar)
	if overrideRedir {
		resp.Type = osin.DATA
	}
	ltx["redirect_uri"] = resp.URL
	logFn := s.Logger.WithContext(ltx).Warnf
	ltx["authorized"] = ar.Authorized
	ltx["state"] = ar.State
	if ar.Authorized {
		logFn = s.Logger.WithContext(ltx).Infof
	}
	logFn("Authorize")
	s.redirectOrOutput(resp, w, r)
}

func (s *Service) loadAccountFromPost(r *http.Request) (*account, error) {
	pw := r.PostFormValue("pw")
	handle := r.PostFormValue("handle")

	app, repo, err := s.findMatchingStorage(baseURL(r)...)
	if err != nil {
		return nil, err
	}
	baseIRI := app.GetLink()

	searchIRI := SearchActorsIRI(baseIRI, ByName(handle), ByType(vocab.PersonType))
	actors, err := repo.Load(searchIRI, filters.NameIs(handle), filters.HasType(vocab.PersonType))
	if err != nil {
		return nil, errUnauthorized
	}
	_ = vocab.OnCollectionIntf(actors, func(col vocab.CollectionInterface) error {
		actors = col.Collection()
		return nil
	})

	var act *account
	var logger = s.Logger.WithContext(lw.Ctx{
		"handle": handle,
		"pass":   mask.S(pw).String(),
	})
	if act, err = checkPw(actors, []byte(pw), repo); err != nil {
		logger.WithContext(lw.Ctx{"error": err.Error()}).Errorf("failed")
		return nil, err
	}

	logger.Infof("Login success")
	return act, nil
}

func reqUrl(r *http.Request) string {
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	return fmt.Sprintf("%s://%s%s", proto, r.Host, r.RequestURI)
}

func (s *Service) renderTemplate(r *http.Request, w http.ResponseWriter, name string, m authModel) {
	wrt := bytes.Buffer{}

	renderOptions.Funcs["redirectURI"] = redirectUri(r)
	err := ren.HTML(&wrt, http.StatusOK, name, m, renderOptions)
	if err == nil {
		_, _ = io.Copy(w, &wrt)
		return
	}
	err = errors.Annotatef(err, "failed to render template")
	s.Logger.WithContext(lw.Ctx{"template": name, "model": fmt.Sprintf("%T", m)}).Errorf("%+s", err)
	status := errors.HttpStatus(err)
	if status == 0 {
		status = http.StatusInternalServerError
	}
	_ = errRenderer.HTML(w, status, "error", err)
}
