package authorize

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"

	"git.sr.ht/~mariusor/cache"
	"github.com/go-ap/client"
)

var DefaultClient atomic.Pointer[http.Client]

func Client(version string) *http.Client {
	if cl := DefaultClient.Load(); cl != nil {
		return cl
	}
	cachePath, err := os.UserCacheDir()
	if err != nil {
		cachePath = os.TempDir()
	}
	ua := fmt.Sprintf("GoActivityPub//authorize (+github.com/go-ap/authorize@%s)", version)
	cl := http.Client{
		Transport: cache.Private(
			client.UserAgentTransport(ua, http.DefaultTransport),
			cache.FS(filepath.Join(cachePath, "authorize")),
		),
	}
	DefaultClient.Store(&cl)
	return &cl
}
