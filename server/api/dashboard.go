package api

import (
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Dashboard serves the built dashboard (the output of npm run build) from a
// directory. A request for a file in the directory gets that file. Any
// other path gets index.html, so the dashboard's client-side routes (such
// as /hosts) load on a refresh or a direct link. API paths never reach it:
// the router answers unknown /api paths with 404.
type Dashboard struct {
	dir   string
	root  http.FileSystem
	files http.Handler
}

// NewDashboard returns a Dashboard for dir, or an error if dir has no
// index.html.
func NewDashboard(dir string) (*Dashboard, error) {
	st, err := os.Stat(filepath.Join(dir, "index.html"))
	if err != nil {
		return nil, fmt.Errorf("dashboard: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("dashboard: %s is not a file", filepath.Join(dir, "index.html"))
	}
	root := http.Dir(dir)
	return &Dashboard{dir: dir, root: root, files: http.FileServer(root)}, nil
}

// Dir is the directory the dashboard is served from.
func (d *Dashboard) Dir() string { return d.dir }

func (d *Dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := path.Clean("/" + r.URL.Path)
	if name != "/" && name != "/index.html" && d.isFile(name) {
		d.files.ServeHTTP(w, r)
		return
	}
	d.serveIndex(w, r)
}

// isFile reports whether name is a regular file under the dashboard
// directory. http.Dir rejects paths that would leave the directory.
func (d *Dashboard) isFile(name string) bool {
	f, err := d.root.Open(name)
	if err != nil {
		return false
	}
	defer f.Close()
	st, err := f.Stat()
	return err == nil && st.Mode().IsRegular()
}

// serveIndex writes index.html. It is read on every request, so a new
// build takes effect without a restart.
func (d *Dashboard) serveIndex(w http.ResponseWriter, r *http.Request) {
	f, err := d.root.Open("/index.html")
	if err != nil {
		http.Error(w, "dashboard index.html is missing", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		http.Error(w, "dashboard index.html is unreadable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, "index.html", st.ModTime(), f)
}

// isAPIPath reports whether p is under /api, which the dashboard never
// serves.
func isAPIPath(p string) bool {
	return p == "/api" || strings.HasPrefix(p, "/api/")
}
