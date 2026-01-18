//go:build dev

package authorize

import (
	"github.com/go-ap/errors"
)

func init() {
	IsDev.Store(true)
	errors.SetIncludeBacktrace(true)
}
