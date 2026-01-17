package authorize

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

func (s *Service) ValidateClient(r *http.Request) (*vocab.Actor, error) {
	_ = r.ParseForm()
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

	app, storage, err := s.findMatchingStorage(baseURL(r)...)
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
	clientActor, err := storage.Load(vocab.IRI(clientID))
	if err != nil && errors.IsNotFound(err) {
		iri := SearchActorsIRI(baseIRI, ByType(vocab.ApplicationType), ByURL(vocab.IRI(clientID)))
		actors, err := storage.Load(iri, filters.SameURL(vocab.IRI(clientID)), filters.HasType(vocab.ApplicationType))
		if err != nil {
			return nil, err
		}
		err = vocab.OnCollectionIntf(actors, func(col vocab.CollectionInterface) error {
			if len(col.Collection()) == 1 {
				clientActor = col.Collection().First()
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if clientActor == nil {
		// TODO(marius): fix IndieAuth automatic client creation
		//    See https://todo.sr.ht/~mariusor/go-activitypub/34
		clientActor, err = NewIndieAuthActor(storage, clientURL, actor)
		if err != nil {
			return nil, err
		}
	}
	id := clientActor.GetID().String()
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

				var it vocab.Item
				// check for existing application actor
				for _, baseIRI := range baseURL(r) {
					clientIRI := filters.ActorsType.IRI(vocab.IRI(baseIRI)).AddPath(ar.Client.GetId())
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
				if vocab.IsNil(it) {
					resp.SetError(osin.E_INVALID_REQUEST, fmt.Sprintf("invalid client: %+s", err))
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
	}

	a.FinishAuthorizeRequest(resp, r, ar)
	if overrideRedir {
		resp.Type = osin.DATA
	}
	ltx["redirect_uri"] = resp.URL
	logFn := s.Logger.WithContext(ltx).Warnf
	if ar != nil {
		ltx["authorized"] = ar.Authorized
		ltx["state"] = ar.State
		if ar.Authorized {
			logFn = s.Logger.WithContext(ltx).Infof
		}
	}
	logFn("Authorize")
	s.redirectOrOutput(resp, w, r)
}

func (s *Service) loadAccountFromPost(r *http.Request) (*account, error) {
	pw := r.PostFormValue("pw")
	handle := r.PostFormValue("handle")

	app, storage, err := s.findMatchingStorage(baseURL(r)...)
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
		_ = vocab.OnCollectionIntf(actors, func(col vocab.CollectionInterface) error {
			actors = col.Collection()
			return nil
		})
	}

	var act *account
	var logger = s.Logger.WithContext(lw.Ctx{
		"handle": handle,
		"pass":   mask.S(pw).String(),
	})
	if act, err = checkPw(actors, []byte(pw), storage); err != nil {
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
