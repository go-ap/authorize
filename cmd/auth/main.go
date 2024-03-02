package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"git.sr.ht/~mariusor/lw"
	w "git.sr.ht/~mariusor/wrapper"
	"github.com/alecthomas/kong"
	"github.com/go-ap/authorize"
	"github.com/go-ap/authorize/internal/config"
	"github.com/go-ap/client"
	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
)

var Auth struct {
	ListenOn string   `name:"listen" help:"The socket to listen on."`
	Env      string   `name:"env" help:"Environment type: ${env_types}" default:"${default_env}"`
	KeyPath  string   `name:"key-path" help:"SSL key path for HTTPS." type:"path"`
	CertPath string   `name:"cert-path" help:"SSL cert path for HTTPS." type:"path"`
	Config   []string `name:"config" help:"Configuration path for .env file" group:"config-options" xor:"config-options"`
	Storage  []string `name:"storage" help:"Storage DSN strings of form type:///path/to/storage." group:"config-options" xor:"config-options"`
}

var l = lw.Dev()

type Config struct {
	Storage string
	Path    string
}

var defaultTimeout = time.Second * 10

var version = "HEAD"

func main() {
	ktx := kong.Parse(
		&Auth,
		kong.Bind(l),
		kong.Vars{
			"env_types":   strings.Join([]string{string(config.DEV), string(config.PROD)}, ", "),
			"default_env": string(config.DEV),
		},
	)
	env := config.DEV
	if config.ValidEnv(Auth.Env) {
		env = config.Env(Auth.Env)
	}

	if build, ok := debug.ReadBuildInfo(); ok && version == "HEAD" && build.Main.Version != "(devel)" {
		version = build.Main.Version
	}

	var stores []authorize.FullStorage
	var err error
	if len(Auth.Storage) > 0 {
		if stores, err = loadStoresFromDSNs(Auth.Storage, env, l.WithContext(lw.Ctx{"log": "storage"})); err != nil {
			l.Errorf("Errors loading storage paths: %+s", err)
		}
	}
	if len(Auth.Config) > 0 {
		if stores, err = loadStoresFromConfigs(Auth.Config, env, l.WithContext(lw.Ctx{"log": "storage"})); err != nil {
			l.Errorf("Errors loading config files: %+s", err)
		}
	}
	if err != nil {
		os.Exit(1)
	}

	r := chi.NewMux()

	h := authorize.Service{
		Stores: stores,
		Client: client.New(
			client.WithLogger(l.WithContext(lw.Ctx{"log": "client"})),
			client.SkipTLSValidation(!env.IsProd()),
		),
		Logger: l.WithContext(lw.Ctx{"log": "auth-service"}),
	}

	logCtx := lw.Ctx{
		"version":  version,
		"listenOn": Auth.ListenOn,
	}
	l = l.WithContext(logCtx)

	routes := func(r chi.Router) {
		// Authorization code endpoint
		r.Get("/authorize", h.Authorize)
		r.Post("/authorize", h.Authorize)
		// Access token endpoint
		r.Post("/token", h.Token)

		r.Group(func(r chi.Router) {
			r.Get("/pw", h.ShowChangePw)
			r.Post("/pw", h.HandleChangePw)
		})
	}

	r.Route("/actors/{id}/oauth", routes)
	r.Route("/oauth", routes)

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

	ctx, cancelFn := context.WithTimeout(context.TODO(), defaultTimeout)
	defer cancelFn()

	// Get start/stop functions for the http server
	srvRun, srvStop := w.HttpServer(setters...)
	l.Infof("Listening for authorization requests")
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

func loadStoresFromDSNs(dsns []string, env config.Env, l lw.Logger) ([]authorize.FullStorage, error) {
	stores := make([]authorize.FullStorage, 0)
	errs := make([]error, 0)
	for _, sto := range dsns {
		typ, path := config.ParseStorageDSN(sto)

		if !config.ValidStorageType(typ) {
			typ = config.DefaultStorage
			path = sto
		}
		conf := config.Storage{Type: typ, Path: path}
		db, err := config.NewStorage(conf, env, l)
		if err != nil {
			errs = append(errs, fmt.Errorf("unable to initialize storage backend [%s]%s: %w", typ, path, err))
			continue
		}
		fs, ok := db.(authorize.FullStorage)
		if !ok {
			errs = append(errs, fmt.Errorf("invalid storage backend %T [%s]%s", db, typ, path))
			continue
		}
		stores = append(stores, fs)
	}
	return stores, errors.Join(errs...)
}

func loadStoresFromConfigs(paths []string, env config.Env, l lw.Logger) ([]authorize.FullStorage, error) {
	stores := make([]authorize.FullStorage, 0)
	errs := make([]error, 0)
	for _, p := range paths {
		if err := godotenv.Load(p); err != nil {
			errs = append(errs, err)
			continue
		}

		opts, err := config.LoadFromEnv(env, defaultTimeout)
		if err != nil {
			errs = append(errs, fmt.Errorf("unable to load configuration %s: %w", p, err))
			continue
		}

		if opts.Listen != "" && Auth.ListenOn == "" {
			Auth.ListenOn = opts.Listen
		}

		st := opts.Storage
		db, err := config.NewStorage(opts.Storage, opts.Env, l)
		if err != nil {
			errs = append(errs, fmt.Errorf("unable to initialize storage backend [%s]%s: %w", st.Type, st.Path, err))
			continue
		}
		fs, ok := db.(authorize.FullStorage)
		if !ok {
			errs = append(errs, fmt.Errorf("invalid storage backend %T [%s]%s", db, st.Type, st.Path))
			continue
		}
		stores = append(stores, fs)
	}
	return stores, errors.Join(errs...)
}
