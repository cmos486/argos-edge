// Package static embeds the built frontend SPA so the argos binary ships
// self-contained.
//
// The frontend build pipeline (Vite) writes its output into this directory
// before `go build` runs: index.html at the root and hashed bundles under
// assets/. A placeholder index.html and an empty assets/.gitkeep are
// committed so plain `go build ./...` succeeds without having to run the
// frontend first; Docker and production builds overwrite the placeholder.
package static

import (
	"embed"
	"io/fs"
)

//go:embed index.html
//go:embed all:assets
var content embed.FS

// FS returns a read-only view of the embedded frontend build.
func FS() fs.FS { return content }
