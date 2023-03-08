package explore

import (
	"fmt"
	"testing"
)

func FuzzPurl(f *testing.F) {
	corpus := []string{
		"pkg:bitbucket/birkenfeld/pygments-main@244fd47e07d1014f0aed9c",
		"pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie",
		"pkg:docker/cassandra@sha256:244fd47e07d1004f0aed9c",
		"pkg:docker/customer/dockerimage@sha256:244fd47e07d1004f0aed9c?repository_url=gcr.io",
		"pkg:gem/jruby-launcher@1.1.2?platform=java",
		"pkg:gem/ruby-advisory-db-check@0.12.4",
		"pkg:github/package-url/purl-spec@244fd47e07d1004f0aed9c",
		"pkg:golang/google.golang.org/genproto#googleapis/api/annotations",
		"pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?packaging=sources",
		"pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?repository_url=repo.spring.io%2Frelease",
		"pkg:npm/%40angular/animation@12.3.1",
		"pkg:npm/foobar@12.3.1",
		"pkg:nuget/EnterpriseLibrary.Common@6.0.1304",
		"pkg:pypi/django@1.11.1",
		"pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
		"pkg:rpm/opensuse/curl@7.56.1-1.1.?arch=i386&distro=opensuse-tumbleweed",
	}

	for _, c := range corpus {
		f.Add(c)
	}

	f.Fuzz(func(t *testing.T, s string) {
		// Test that parsing doesn't panic.
		_, _ = parsePurl(s)
		fmt.Print(s)
	})
}

func TestPurl(t *testing.T) {

	for _, tc := range []struct {
		input string
		want  string
	}{{
		"pkg:bitbucket/birkenfeld/pygments-main@244fd47e07d1014f0aed9c",
		"https://www.bitbucket.org/birkenfeld/pygments-main/changeset/244fd47e07d1014f0aed9c",
		// }, {
		// 	"pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie", "",
	}, {
		"pkg:docker/cassandra@sha256:244fd47e07d1004f0aed9c",
		"/?image=index.docker.io/library/cassandra@sha256:244fd47e07d1004f0aed9c",
	}, {
		"pkg:docker/customer/dockerimage@sha256:244fd47e07d1004f0aed9c?repository_url=gcr.io",
		"/?image=gcr.io/customer/dockerimage@sha256:244fd47e07d1004f0aed9c",
	}, {
		// TODO: More oci fields.
		"pkg:oci/customer/dockerimage@sha256:244fd47e07d1004f0aed9c?repository_url=gcr.io",
		"/?image=gcr.io/customer/dockerimage@sha256:244fd47e07d1004f0aed9c",
		//}, {
		//	"pkg:gem/jruby-launcher@1.1.2?platform=java", "",
		//}, {
		//	"pkg:gem/ruby-advisory-db-check@0.12.4", "",
	}, {
		"pkg:github/package-url/purl-spec@244fd47e07d1004f0aed9c",
		"https://github.com/package-url/purl-spec/tree/244fd47e07d1004f0aed9c",
	}, {
		"pkg:apk/alpine/foo@1.2.3?arch=x86_64",
		"https://pkgs.alpinelinux.org/packages?name=foo&branch=edge&arch=x86_64",
		//}, {
		//	"pkg:golang/google.golang.org/genproto#googleapis/api/annotations", "",
		//}, {
		//	"pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?packaging=sources", "",
		//}, {
		//	"pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?repository_url=repo.spring.io%2Frelease", "",
		//}, {
		//	"pkg:npm/%40angular/animation@12.3.1", "",
		//}, {
		//	"pkg:npm/foobar@12.3.1", "",
		//}, {
		//	"pkg:nuget/EnterpriseLibrary.Common@6.0.1304", "",
		//}, {
		//	"pkg:pypi/django@1.11.1", "",
		//}, {
		//	"pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25", "",
		//}, {
		//	"pkg:rpm/opensuse/curl@7.56.1-1.1.?arch=i386&distro=opensuse-tumbleweed", "",
	}} {
		p, err := parsePurl(tc.input)
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.url("example.com")
		if err != nil {
			t.Fatalf("purl(%q).url(): %v", tc.input, err)
		}
		if got != tc.want {
			t.Errorf("purl(%q).url(): got: %q, want: %q", tc.input, got, tc.want)
		}
	}
}
