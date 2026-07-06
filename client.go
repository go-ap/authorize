package authorize

import (
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"

	"git.sr.ht/~mariusor/cache"
)

var DefaultClient atomic.Pointer[http.Client]

func Client() *http.Client {
	if cl := DefaultClient.Load(); cl != nil {
		return cl
	}
	cachePath, err := os.UserCacheDir()
	if err != nil {
		cachePath = os.TempDir()
	}
	cacheTransp := cache.Private(http.DefaultTransport, cache.FS(filepath.Join(cachePath, "authorize")))
	cl := http.Client{Transport: cacheTransp}
	DefaultClient.Store(&cl)
	return &cl
}
