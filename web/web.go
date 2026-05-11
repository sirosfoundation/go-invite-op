package web

import (
	"embed"
	"html/template"
	"io"
	"io/fs"
)

//go:embed templates/index.html
var indexHTML string

//go:embed all:dist
var distFS embed.FS

var indexTmpl = template.Must(template.New("index").Parse(indexHTML))

type IndexTemplateData struct {
	SessionID string
	Error     string
	Email     string
}

func ExecuteIndexTemplate(wr io.Writer, data IndexTemplateData) error {
	return indexTmpl.Execute(wr, data)
}

func GetAssetFS() fs.FS {
	sub, _ := fs.Sub(distFS, "dist")
	return sub
}
