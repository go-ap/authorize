package authorize

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"git.sr.ht/~mariusor/lw"
	"git.sr.ht/~mariusor/mask"
	vocab "github.com/go-ap/activitypub"
	"github.com/go-ap/errors"
	"github.com/go-ap/filters"
	"github.com/go-chi/chi/v5"
)

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
		_ = vocab.OnCollectionIntf(actors, func(col vocab.CollectionInterface) error {
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

// ShowChangePw
func (s *Service) ShowChangePw(w http.ResponseWriter, r *http.Request) {
	actor := s.loadActorFromOauth2Session(w, r)
	if actor == nil {
		s.HandleError(errors.NotValidf("Unable to load actor from session")).ServeHTTP(w, r)
		return
	}

	app, _, err := s.findMatchingStorage(baseURL(r)...)
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

	_, storage, err := s.findMatchingStorage(baseURL(r)...)
	if err != nil {
		s.HandleError(err).ServeHTTP(w, r)
		return
	}

	if err = storage.PasswordSet(actor.ID, []byte(pw)); err != nil {
		s.HandleError(errors.NotValidf("Unable to change password")).ServeHTTP(w, r)
		return
	}

	s.Logger.WithContext(lw.Ctx{
		"handle": actor.PreferredUsername.String(),
		"pass":   mask.S(pw).String(),
	}).Infof("Changed pw")

	_ = storage.RemoveAuthorize(tok)
}

func (s *Service) loadActorFromOauth2Session(w http.ResponseWriter, r *http.Request) *vocab.Actor {
	notF := errors.NotFoundf("Not found")
	// TODO(marius): we land on this handler, coming from an email link containing a token identifying the Actor
	tok := r.URL.Query().Get("s")
	if len(tok) == 0 {
		s.HandleError(notF).ServeHTTP(w, r)
		return nil
	}
	_, storage, err := s.findMatchingStorage(baseURL(r)...)
	if err != nil {
		s.HandleError(err).ServeHTTP(w, r)
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
