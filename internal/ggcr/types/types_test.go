package types

import "testing"

func TestMediaTypePredicates(t *testing.T) {
	cases := []struct {
		mt   MediaType
		want map[string]bool // predicate -> expected
	}{
		{
			OCIManifestSchema1,
			map[string]bool{"image": true, "index": false, "config": false, "schema1": false, "distributable": true},
		},
		{
			DockerManifestSchema2,
			map[string]bool{"image": true, "index": false, "config": false, "schema1": false, "distributable": true},
		},
		{
			OCIImageIndex,
			map[string]bool{"image": false, "index": true, "config": false, "schema1": false, "distributable": true},
		},
		{
			DockerManifestList,
			map[string]bool{"image": false, "index": true, "config": false, "schema1": false, "distributable": true},
		},
		{
			OCIConfigJSON,
			map[string]bool{"image": false, "index": false, "config": true, "schema1": false, "distributable": true},
		},
		{
			DockerConfigJSON,
			map[string]bool{"image": false, "index": false, "config": true, "schema1": false, "distributable": true},
		},
		{
			DockerManifestSchema1,
			map[string]bool{"image": false, "index": false, "config": false, "schema1": true, "distributable": true},
		},
		{
			DockerManifestSchema1Signed,
			map[string]bool{"image": false, "index": false, "config": false, "schema1": true, "distributable": true},
		},
		{
			OCIRestrictedLayer,
			map[string]bool{"image": false, "index": false, "config": false, "schema1": false, "distributable": false},
		},
		{
			OCIUncompressedRestrictedLayer,
			map[string]bool{"image": false, "index": false, "config": false, "schema1": false, "distributable": false},
		},
		{
			DockerForeignLayer,
			map[string]bool{"image": false, "index": false, "config": false, "schema1": false, "distributable": false},
		},
		{
			OCILayer,
			map[string]bool{"image": false, "index": false, "config": false, "schema1": false, "distributable": true},
		},
	}

	for _, tc := range cases {
		t.Run(string(tc.mt), func(t *testing.T) {
			if got, want := tc.mt.IsImage(), tc.want["image"]; got != want {
				t.Errorf("IsImage() = %v, want %v", got, want)
			}
			if got, want := tc.mt.IsIndex(), tc.want["index"]; got != want {
				t.Errorf("IsIndex() = %v, want %v", got, want)
			}
			if got, want := tc.mt.IsConfig(), tc.want["config"]; got != want {
				t.Errorf("IsConfig() = %v, want %v", got, want)
			}
			if got, want := tc.mt.IsSchema1(), tc.want["schema1"]; got != want {
				t.Errorf("IsSchema1() = %v, want %v", got, want)
			}
			if got, want := tc.mt.IsDistributable(), tc.want["distributable"]; got != want {
				t.Errorf("IsDistributable() = %v, want %v", got, want)
			}
		})
	}
}
