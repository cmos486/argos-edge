package api

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// SPAHandler serves the embedded single-page app.
//
// Behaviour:
//   - existing files under assets/* are served with an immutable 1y cache
//     (Vite emits hashed filenames, so any change produces a new URL);
//   - index.html and other root files are served with no-cache so deploys
//     never pin clients to a stale bundle;
//   - any path that does not resolve to a real file falls back to
//     index.html so client-side routing works on deep links and reloads.
//
// The handler is mounted as a catch-all; chi dispatches /api/* and
// /healthz to their specific handlers first, so they never reach here.
func SPAHandler(root fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(root))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "" || name == "." {
			serveIndex(w, r, fileServer)
			return
		}

		f, err := root.Open(name)
		if err != nil {
			serveIndex(w, r, fileServer)
			return
		}
		info, statErr := f.Stat()
		f.Close()
		if statErr != nil || info.IsDir() {
			serveIndex(w, r, fileServer)
			return
		}

		if strings.HasPrefix(name, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(w, r)
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request, fs http.Handler) {
	w.Header().Set("Cache-Control", "no-cache")
	r2 := r.Clone(r.Context())
	r2.URL.Path = "/"
	r2.URL.RawPath = ""
	fs.ServeHTTP(w, r2)
}
