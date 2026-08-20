package config

import (
	"io/fs"
	"os"
	"path/filepath"

	"git.sr.ht/~mariusor/lw"
	"git.sr.ht/~mariusor/storage-all"
)

const DefaultStorage = StorageFS

func Storage(c StorageConfig, env Env, l lw.Logger) (storage.FullStorage, error) {
	hostname := ""
	if c.Type == StorageBadger {
		_ = fs.WalkDir(os.DirFS(c.Path), ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() || p == "." {
				return nil
			}
			parent, base := filepath.Split(p)
			if parent == "" && base != "" {
				hostname = base
				return fs.SkipAll
			}
			return nil
		})
	}
	initFns := []storage.InitFn{
		storage.WithPath(c.Path),
		storage.WithType(storage.Type(c.Type)),
		storage.WithEnv(string(env)),
		storage.WithLogger(l),
	}
	if hostname != "" {
		initFns = append(initFns, storage.WithHostname(hostname))
	}
	return storage.New(initFns...)
}
