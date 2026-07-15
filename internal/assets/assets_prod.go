//go:build !dev

package assets

import "embed"

const TemplatesPath = "templates"

//go:embed templates/*
var Templates embed.FS
