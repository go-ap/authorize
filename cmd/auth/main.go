package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"git.sr.ht/~mariusor/lw"
	m "git.sr.ht/~mariusor/servermux"
	w "git.sr.ht/~mariusor/wrapper"
	"github.com/alecthomas/kong"
	"github.com/go-ap/authorize"
	"github.com/go-ap/authorize/internal/config"
	"github.com/go-ap/client"
	"github.com/go-ap/errors"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
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

type corsLogger func(string, ...any)

func (c corsLogger) Printf(f string, v ...interface{}) {
	c(f, v...)
}

func checkOriginForBlockedActors(r *http.Request, origin string) bool {
	return true
}

const defaultGraceWait = 1500 * time.Millisecond

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
	if len(stores) == 0 {
		l.Errorf("Unable to find any valid storage path")
		os.Exit(1)
	}

	r := chi.NewMux()

	ua := fmt.Sprintf("GoActivityPub//authorize (+github.com/go-ap/authorize@%s)", version)
	baseClient := &http.Client{
		Transport: client.UserAgentTransport(ua, http.DefaultTransport),
	}
	h := authorize.Service{
		Stores: stores,
		Client: client.New(
			client.WithHTTPClient(baseClient),
			client.WithLogger(l.WithContext(lw.Ctx{"log": "client"})),
			client.SkipTLSValidation(!env.IsProd()),
		),
		Logger: l.WithContext(lw.Ctx{"log": "auth"}),
	}

	logCtx := lw.Ctx{
		"version":  version,
		"listenOn": Auth.ListenOn,
	}
	l = l.WithContext(logCtx)

	allowedOrigins := []string{"https://*"}
	if !env.IsProd() {
		allowedOrigins = append(allowedOrigins, "http://*")
	}
	c := cors.New(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
		AllowOriginFunc:  checkOriginForBlockedActors,
		MaxAge:           int(time.Hour.Seconds()),
		Debug:            !authorize.InDebugMode,
	})
	c.Log = corsLogger(l.WithContext(lw.Ctx{"log": "cors"}).Tracef)

	routes := func(r chi.Router) {
		r.Use(c.Handler)
		// Authorization code endpoint
		r.Get("/authorize", h.Authorize)
		r.Post("/authorize", h.Authorize)
		// Access token endpoint
		r.Post("/token", h.Token)
		r.Post("/client", h.ClientRegistration)

		r.Group(func(r chi.Router) {
			r.Get("/pw", h.ShowChangePw)
			r.Post("/pw", h.HandleChangePw)
		})
	}

	r.Route("/actors/{id}/oauth", routes)
	r.Route("/oauth", routes)
	r.NotFound(errors.NotFound.ServeHTTP)

	setters := []m.SetFn{m.Handler(r)}

	if len(Auth.CertPath)+len(Auth.KeyPath) > 0 {
		setters = append(setters, m.WithTLSCert(Auth.CertPath, Auth.KeyPath))
	}
	dir, _ := filepath.Split(Auth.ListenOn)
	if Auth.ListenOn == "systemd" {
		setters = append(setters, m.OnSystemd())
	} else if _, err := os.Stat(dir); err == nil {
		setters = append(setters, m.OnSocket(Auth.ListenOn))
		defer func() { _ = os.RemoveAll(Auth.ListenOn) }()
	} else {
		setters = append(setters, m.OnTCP(Auth.ListenOn))
	}

	ctx, cancelFn := context.WithCancel(context.TODO())
	defer cancelFn()

	l = l.WithContext(logCtx)

	// Get start/stop functions for the http server
	httpSrv, err := m.HttpServer(setters...)
	if err != nil {
		l.WithContext(lw.Ctx{"err": err}).Errorf("Failed to initialize HTTP server")
		os.Exit(1)
	}

	s, err := m.Mux(m.WithServer(httpSrv), m.GracefulWait(defaultGraceWait))
	stopFn := func(ctx context.Context) error {
		l.Infof("Shutting down")
		for _, st := range stores {
			st.Close()
		}
		return s.Stop(ctx)
	}

	exitWithErrOrInterrupt := func(err error, exit chan<- error) {
		if err == nil {
			err = w.Interrupt
		}
		exit <- err
	}

	l.Infof("Listening for authorization requests")
	err = w.RegisterSignalHandlers(w.SignalHandlers{
		syscall.SIGHUP: func(_ chan<- error) {
			l.Debugf("SIGHUP received, reloading configuration")
		},
		syscall.SIGUSR1: func(_ chan<- error) {
			authorize.InMaintenanceMode = !authorize.InMaintenanceMode
			l.WithContext(lw.Ctx{"maintenance": authorize.InMaintenanceMode}).Debugf("SIGUSR1 received")
		},
		syscall.SIGUSR2: func(_ chan<- error) {
			authorize.InDebugMode = !authorize.InDebugMode
			l.WithContext(lw.Ctx{"debug": authorize.InDebugMode}).Debugf("SIGUSR2 received")
		},
		syscall.SIGINT: func(exit chan<- error) {
			l.WithContext(lw.Ctx{"wait": defaultGraceWait}).Debugf("SIGINT received, stopping")
			exitWithErrOrInterrupt(stopFn(ctx), exit)
		},
		syscall.SIGTERM: func(exit chan<- error) {
			l.WithContext(lw.Ctx{"wait": defaultGraceWait}).Debugf("SIGTERM received, force stopping")
			exitWithErrOrInterrupt(stopFn(ctx), exit)
		},
		syscall.SIGQUIT: func(exit chan<- error) {
			l.Debugf("SIGQUIT received, ungraceful force stopping")
			// NOTE(marius): to skip any graceful wait on the listening server, cancel the context first
			cancelFn()
			exitWithErrOrInterrupt(stopFn(ctx), exit)
		},
	}).Exec(ctx, s.Start)

	if err != nil {
		l.WithContext(lw.Ctx{"err": err}).Errorf("Failed")
		ktx.Exit(1)
	} else {
		l.Infof("Stopped")
	}
	ktx.Exit(0)
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
		conf := config.StorageConfig{Type: typ, Path: path}
		db, err := config.Storage(conf, env, l)
		if err != nil {
			errs = append(errs, fmt.Errorf("unable to initialize storage backend [%s]%s: %w", typ, path, err))
			continue
		}
		fs, ok := db.(authorize.FullStorage)
		if !ok {
			errs = append(errs, fmt.Errorf("invalid storage backend %T [%s]%s", db, typ, path))
			continue
		}
		if err = fs.Open(); err != nil {
			errs = append(errs, fmt.Errorf("unable to open storage backend %T [%s]%s", db, typ, path))
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
		db, err := config.Storage(opts.Storage, opts.Env, l)
		if err != nil {
			errs = append(errs, fmt.Errorf("unable to initialize storage backend [%s]%s: %w", st.Type, st.Path, err))
			continue
		}
		fs, ok := db.(authorize.FullStorage)
		if !ok {
			errs = append(errs, fmt.Errorf("invalid storage backend %T [%s]%s", db, st.Type, st.Path))
			continue
		}
		if err = fs.Open(); err != nil {
			errs = append(errs, fmt.Errorf("unable to open storage backend %T [%s]%s", db, st.Type, st.Path))
			continue
		}
		stores = append(stores, fs)
	}
	return stores, errors.Join(errs...)
}
