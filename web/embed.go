// Package web contains the build-free administrative interface.
package web

import "embed"

// Files is embedded into the application binary; no asset server or CDN is needed.
//
//go:embed index.html app.js theme.js styles.css favicon.svg fonts/*.woff2 licenses/*.txt
var Files embed.FS
