package apk

import (
	"text/template"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

var (
	landingTmpl *template.Template
	headerTmpl  *template.Template
	bodyTmpl    *template.Template
	oauthTmpl   *template.Template
)

func init() {
	landingTmpl = template.Must(template.New("landingTemplate").Parse(landingTemplate))
	headerTmpl = template.Must(template.New("headerTemplate").Parse(headerTemplate))
	bodyTmpl = template.Must(template.New("bodyTemplate").Parse(bodyTemplate))
	oauthTmpl = template.Must(template.New("oauthTemplate").Parse(oauthTemplate))
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
{{ end}}
{{ if .Apks }}
<h4>Local APKs</h4>
<p>
{{ range .Apks }}<li><a href="/file/{{.}}">{{.}}</a></li>{{end}}
</p>
{{ end}}
<p>
<h4>Interesting examples</h4>
<ul>
  <li><a href="/https/packages.wolfi.dev/os/aarch64/APKINDEX.tar.gz/APKINDEX">packages.wolfi.dev/os/aarch64</a></li>
  <li><a href="/https/packages.wolfi.dev/os/x86_64/APKINDEX.tar.gz/APKINDEX">packages.wolfi.dev/os/x86_64</a></li>
  <li><a href="/https/packages.cgr.dev/os/aarch64/APKINDEX.tar.gz/APKINDEX">packages.cgr.dev/os/aarch64</a></li>
  <li><a href="/https/packages.cgr.dev/os/x86_64/APKINDEX.tar.gz/APKINDEX">packages.cgr.dev/os/x86_64</a></li>
  <li><a href="/https/packages.cgr.dev/extras/aarch64/APKINDEX.tar.gz/APKINDEX">packages.cgr.dev/extras/aarch64</a></li>
  <li><a href="/https/packages.cgr.dev/extras/x86_64/APKINDEX.tar.gz/APKINDEX">packages.cgr.dev/extras/x86_64</a></li>
  <li><a href="/https/dl-cdn.alpinelinux.org/alpine/edge/main/aarch64/APKINDEX.tar.gz/APKINDEX">dl-cdn.alpinelinux.org/alpine/edge/main/aarch64</a></li>
  <li><a href="/https/dl-cdn.alpinelinux.org/alpine/edge/main/armhf/APKINDEX.tar.gz/APKINDEX">dl-cdn.alpinelinux.org/alpine/edge/main/armhf</a></li>
  <li><a href="/https/dl-cdn.alpinelinux.org/alpine/edge/main/armv7/APKINDEX.tar.gz/APKINDEX">dl-cdn.alpinelinux.org/alpine/edge/main/armv7</a></li>
  <li><a href="/https/dl-cdn.alpinelinux.org/alpine/edge/main/mips64/APKINDEX.tar.gz/APKINDEX">dl-cdn.alpinelinux.org/alpine/edge/main/mips64</a></li>
  <li><a href="/https/dl-cdn.alpinelinux.org/alpine/edge/main/ppc64le/APKINDEX.tar.gz/APKINDEX">dl-cdn.alpinelinux.org/alpine/edge/main/ppc64le</a></li>
  <li><a href="/https/dl-cdn.alpinelinux.org/alpine/edge/main/riscv64/APKINDEX.tar.gz/APKINDEX">dl-cdn.alpinelinux.org/alpine/edge/main/riscv64</a></li>
  <li><a href="/https/dl-cdn.alpinelinux.org/alpine/edge/main/s390x/APKINDEX.tar.gz/APKINDEX">dl-cdn.alpinelinux.org/alpine/edge/main/s390x</a></li>
  <li><a href="/https/dl-cdn.alpinelinux.org/alpine/edge/main/x86/APKINDEX.tar.gz/APKINDEX">dl-cdn.alpinelinux.org/alpine/edge/main/x86</a></li>
  <li><a href="/https/dl-cdn.alpinelinux.org/alpine/edge/main/x86_64/APKINDEX.tar.gz/APKINDEX">dl-cdn.alpinelinux.org/alpine/edge/main/x86_64</a></li>
</ul>
</p>
</body>
</html>
`

	oauthTemplate = `
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
It looks like we encountered an auth error:
</p>
<code>
{{.Error}}
</code>
<p>
If you trust <a class="mt" href="https://github.com/jonjohnsonjr">me</a>, click <a href="{{.Redirect}}">here</a> for oauth to use your own credentials.
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
{{ if .JQ }}<h4><span class="noselect">$</span>{{.JQ}}</h4>{{ end }}
{{ if .PAXRecords }}<div><table><tr><th>PAXRecords</th><th></th></tr>
{{ range $k, $v := .PAXRecords }}<tr><td>{{$k}}</td><td>{{$v}}</td></tr>{{ end }}
</table></div>{{ end }}`

	footer = `
</body>
</html>
`
)

type Landing struct {
	Indices []string
	Apks    []string
}

type RepoParent struct {
	Parent    string
	Child     string
	Separator string
}

type OauthData struct {
	Error    string
	Redirect string
}

type TitleData struct {
	Title string
}
type CosignTag struct {
	Tag   string
	Short string
}

type HeaderData struct {
	ShowSearch       bool
	Expanded         bool
	Full             bool
	Search           string
	Depend           string
	Provide          string
	Repo             string
	CosignTags       []CosignTag
	Message          string
	JQ               string
	PAXRecords       map[string]string
	Reference        string
	Up               *RepoParent
	Descriptor       *v1.Descriptor
	Handler          string
	EscapedMediaType string
	MediaTypeLink    string
	SizeLink         string
	Referrers        bool
	Subject          string
}
