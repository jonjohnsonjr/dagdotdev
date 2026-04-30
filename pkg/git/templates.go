package git

import (
	"text/template"
)

var (
	headerTmpl *template.Template
	bodyTmpl   *template.Template
)

func init() {
	headerTmpl = template.Must(template.New("headerTemplate").Parse(headerTemplate))
	bodyTmpl = template.Must(template.New("bodyTemplate").Parse(bodyTemplate))
}

const (
	landing = `
<html>
<body>
<head>
<title>Git Explorer</title>
<link rel="icon" href="/favicon.svg">
<style>
.link {
	position: relative;
	bottom: .125em;
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
<h1><a class="top" href="/">🪢 <span class="link">Git Explorer</span></a></h1>
<p>
	Enter a git repo URL:
</p>
<form action="/" method="GET" autocomplete="off" spellcheck="false">
<input size="100" type="text" name="url" value=""/>
<input type="submit" />
</form>
<p>
<h4>Interesting examples</h4>
<ul>
	<li><a href="/?url=https://github.com/jonjohnsonjr/dagdotdev@HEAD">github.com/jonjohnsonjr/dagdotdev</a></li>
	<li><a href="/?url=https://github.com/wolfi-dev/os@HEAD">github.com/wolfi-dev/os</a></li>
</ul>
</p>
<h3>FAQ</h3>
<h4>How does this work?</h4>
<p>
This service lives on <a href="https://cloud.run">Cloud Run</a> and uses (a forked version of) <a href="https://github.com/rsc/gitfs">rsc.io/gitfs</a> for git interactions.
</p>
<h4>Is this open source?</h4>
<p>Yes! See <a href="/https/github.com/jonjohnsonjr/dagdotdev@HEAD/internal/git/">here</a>.</p>
<h4>But why?</h4>
<p>GitHub truncates results if you have over 1000 files in a directory (see the wolfi example).</p>
<p>It also takes several seconds to load every page because of the React mind virus.</p>
<p>I value my time and the environment too much to continue to use GitHub's web UI for casual browsing.</p>
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

.noselect {
	user-select: none;
	-webkit-user-select: none;
	width: fit-content;
	overflow-wrap: none;
	padding-right: 1em;
	text-align: right;
	white-space: nowrap;
}
</style>
</head>
`

	bodyTemplate = `
<body>
<div>
<h1><a class="top" href="/">🪢 <span class="link">Git Explorer</span></a></h1>
<h2><a class="mt" href="{{.RepoLink}}">{{.Repo}}</a>{{ if .Ref }}<a class="mt" href="/?url={{ .Repo }}">@</a><a class="mt" href="{{ .RefLink }}">{{ .Ref }}</a>{{if .Path }}/<a class="mt" href="{{ .PathLink }}">{{ .Path }}</a>{{ end }}{{ end }}</h2>
</div>
{{ if .Message }}<p>{{.Message}}</p>{{ end }}
{{ if .JQ }}<h4><span class="noselect">$</span>{{.JQ}}</h4>{{ end }}`

	footer = `
</body>
</html>
`
)

type TitleData struct {
	Title string
}

type HeaderData struct {
	Message string
	JQ      string

	Repo     string
	RepoLink string
	Ref      string
	RefLink  string
	Path     string
	PathLink string
}
