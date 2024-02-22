package main

import (
	"context"
	"github.com/go-ap/authorize"
	"github.com/go-ap/client"
	"github.com/go-chi/chi/v5"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"git.sr.ht/~mariusor/lw"
	w "git.sr.ht/~mariusor/wrapper"
	"github.com/alecthomas/kong"
	"github.com/go-ap/authorize/internal/config"
)

var Auth struct {
	ListenOn string   `required:"" name:"listen" help:"The socket to listen on." default:"localhost:3666"`
	KeyPath  string   `name:"key-path" help:"SSL key path for HTTPS." type:"path"`
	CertPath string   `name:"cert-path" help:"SSL cert path for HTTPS." type:"path"`
	Storage  []string `required:"" flag:"" name:"storage" help:"Storage DSN strings of form type:///path/to/storage."`
}

const (
	StorageBoltDB = "boltdb"
	StorageBadger = "badger"
	StorageSqlite = "sqlite"
	StorageFS     = "fs"
)

var l = lw.Dev()

type Config struct {
	Storage string
	Path    string
}

func exit(errs ...error) {
	if len(errs) == 0 {
		os.Exit(0)
		return
	}
	for _, err := range errs {
		l.Errorf("%s", err)
	}
	os.Exit(-1)
}

func main() {
	ktx := kong.Parse(&Auth, kong.Bind(l))

	stores := make([]authorize.FullStorage, 0)
	for _, sto := range Auth.Storage {
		typ, path := config.ParseStorageDsn(sto)

		if !config.ValidStorageType(typ) {
			typ = config.DefaultStorage
			path = sto
		}
		conf := config.Storage{Type: typ, Path: path}
		db, err := config.NewStorage(conf, l)
		if err != nil {
			l.Errorf("unable to initialize storage backend [%s]%s: %w", typ, path, err)
			continue
		}
		fs, ok := db.(authorize.FullStorage)
		if !ok {
			l.Errorf("invalid storage backend %T [%s]%s", db, typ, path)
			continue
		}
		stores = append(stores, fs)
	}

	env := config.DEV

	r := chi.NewMux()

	h := authorize.Service{
		Stores: stores,
		Client: client.New(
			client.WithLogger(l.WithContext(lw.Ctx{"log": "client"})),
			client.SkipTLSValidation(!env.IsProd()),
		),
		Logger: l.WithContext(lw.Ctx{"log": "auth-service"}),
	}

	r.Route("/oauth", func(r chi.Router) {
		// Authorization code endpoint
		r.Get("/authorize", h.Authorize)
		r.Post("/authorize", h.Authorize)
		// Access token endpoint
		r.Post("/token", h.Token)

		r.Group(func(r chi.Router) {
			r.Get("/login", h.ShowLogin)
			r.Post("/login", h.HandleLogin)
			r.Get("/pw", h.ShowChangePw)
			r.Post("/pw", h.HandleChangePw)
		})
	})

	setters := []w.SetFn{w.Handler(r)}

	if len(Auth.CertPath)+len(Auth.KeyPath) > 0 {
		setters = append(setters, w.WithTLSCert(Auth.CertPath, Auth.KeyPath))
	}
	dir, _ := filepath.Split(Auth.ListenOn)
	if Auth.ListenOn == "systemd" {
		setters = append(setters, w.OnSystemd())
	} else if _, err := os.Stat(dir); err == nil {
		setters = append(setters, w.OnSocket(Auth.ListenOn))
		defer func() { os.RemoveAll(Auth.ListenOn) }()
	} else {
		setters = append(setters, w.OnTCP(Auth.ListenOn))
	}

	ctx, cancelFn := context.WithTimeout(context.TODO(), time.Second*10)
	defer cancelFn()

	// Get start/stop functions for the http server
	srvRun, srvStop := w.HttpServer(setters...)
	l.Infof("Listening for authorization requests on %s", Auth.ListenOn)
	stopFn := func() {
		if err := srvStop(ctx); err != nil {
			l.Errorf("%+v", err)
		}
	}
	defer stopFn()

	exit := w.RegisterSignalHandlers(w.SignalHandlers{
		syscall.SIGHUP: func(_ chan int) {
			l.Infof("SIGHUP received, reloading configuration")
		},
		syscall.SIGINT: func(exit chan int) {
			l.Infof("SIGINT received, stopping")
			exit <- 0
		},
		syscall.SIGTERM: func(exit chan int) {
			l.Infof("SIGITERM received, force stopping")
			exit <- 0
		},
		syscall.SIGQUIT: func(exit chan int) {
			l.Infof("SIGQUIT received, force stopping with core-dump")
			exit <- 0
		},
	}).Exec(func() error {
		if err := srvRun(); err != nil {
			l.Errorf("%+v", err)
			return err
		}
		return nil
	})
	if exit == 0 {
		l.Infof("Shutting down")
	}

	ktx.Exit(exit)
}
