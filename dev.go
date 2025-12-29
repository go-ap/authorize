//go:build dev

package authorize

import "github.com/go-ap/errors"

var IsDev = true

func init() {
	errors.SetIncludeBacktrace(true)
}
