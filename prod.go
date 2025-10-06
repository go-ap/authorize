//go:build !dev

package authorize

import "github.com/go-ap/errors"

func init() {
	errors.IncludeBacktrace = false
}

var IsDev = false
