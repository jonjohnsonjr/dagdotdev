package apk

import (
	"text/template"
)

var (
	landingTmpl *template.Template
	headerTmpl  *template.Template
	bodyTmpl    *template.Template
)

func init() {
	landingTmpl = template.Must(template.New("landingTemplate").Parse(landingTemplate))
	headerTmpl = template.Must(template.New("headerTemplate").Parse(headerTemplate))
	bodyTmpl = template.Must(template.New("bodyTemplate").Parse(bodyTemplate))
}

const (
	landingTemplate = `
<html>
<body>
<head>
<title>APK Explorer</title>
<link rel="icon" href="/favicon.svg">
<style>
.mt:hover {
	text-decoration: underline;
}

.mt {
	color: inherit;
	text-decoration: inherit;
}

.link {
	position: relative;
	bottom: .125em;
}

.crane {
	height: 1em;
	width: 1em;
}

.top {
	color: inherit;
	text-decoration: inherit;
}

body {
	font-family: monospace;
	width: fit-content;
	overflow-wrap: anywhere;
	padding: 12px;
}
</style>
</head>
<h1><a class="top" href="/">🐙 <span class="link">APK Explorer</span></a></h1>
<p>
	Enter an APKINDEX.tar.gz URL:
</p>
<form action="/" method="GET" autocomplete="off" spellcheck="false">
<input size="100" type="text" name="url" value=""/>
<input type="submit" />
</form>
{{ if .Indices }}
<h4>Local APKINDEX</h4>
<p>
{{ range .Indices }}<li><a href="/file/{{.}}/APKINDEX">{{.}}</a></li>{{end}}
</p>
{{ end }}
{{ if .Apks }}
<h4>Local APKs</h4>
<p>
{{ range .Apks }}<li><a href="/file/{{.}}">{{.}}</a></li>{{end}}
</p>
{{ end }}
<p>
<h4>Interesting examples</h4>
<ul>
{{ range .Examples }}
  <li><a href="/https/{{.}}/APKINDEX.tar.gz/APKINDEX">{{.}}</a></li>
{{ end }}
</ul>
</p>
</body>
</html>
`

	headerTemplate = `
<html>
<head>
<title>{{.Title}}</title>
<link rel="icon" href="/favicon.svg">
<style>
.mt:hover {
	text-decoration: underline;
}

.mt {
	color: inherit;
	text-decoration: inherit;
}

.link {
	position: relative;
	bottom: .125em;
}

.crane {
	height: 1em;
	width: 1em;
}

.top {
	color: inherit;
	text-decoration: inherit;
}

body {
	font-family: monospace;
	width: fit-content;
	overflow-wrap: anywhere;
	padding: 12px;
}

pre {
	white-space: pre-wrap;
}

.indent {
	margin-left: 2em;
}

.noselect {
	user-select: none;
	-webkit-user-select: none;
	width: fit-content;
	overflow-wrap: none;
	padding-right: 1em;
	text-align: right;
	white-space: nowrap;
}

td {
	vertical-align: top;
}

th {
	text-align: left;
}
</style>
</head>
`

	bodyTemplate = `
<body>
<div>
<h1><a class="top" href="/">🐙 <span class="link">APK Explorer</span></a></h1>
</div>
{{ if .ShowSearch }}</p>
<p>
<form action="" method="GET" autocomplete="off" spellcheck="false">
<input type="hidden" name="full" value="{{.Full}}"/>
<input size="100" type="text" name="search" value="{{.Search}}"/>
<input type="submit" value="Search" />
</p>
<details{{if .Expanded}} open{{end}}>
<summary>Advanced Search</summary>
<p><input size="100" type="text" name="depend" value="{{.Depend}}" placeholder="Depends"/></p>
<p><input size="100" type="text" name="provide" value="{{.Provide}}" placeholder="Provides"/></p>
</details>
</form>
<p>{{ end }}
{{ if .Message }}<p>{{.Message}}</p>{{ end }}
{{ if .JQ }}<h4><span style="padding:0;" class="noselect">$</span>{{.JQ}}</h4>{{ end }}
{{ if .PAXRecords }}<div><table><tr><th>PAXRecords</th><th></th></tr>
{{ range $k, $v := .PAXRecords }}<tr><td>{{$k}}</td><td>{{$v}}</td></tr>{{ end }}
</table></div>{{ end }}`

	footer = `
</body>
</html>
`
)

type Landing struct {
	Examples []string
	Indices  []string
	Apks     []string
}

type TitleData struct {
	Title string
}

type HeaderData struct {
	ShowSearch bool
	Expanded   bool
	Full       bool
	Search     string
	Depend     string
	Provide    string
	Message    string
	JQ         string
	PAXRecords map[string]string
	SizeLink   string // TODO: We don't use this, I think.
}
