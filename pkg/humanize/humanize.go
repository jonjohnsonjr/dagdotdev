// Package humanize formats values for display.
package humanize

import (
	"fmt"
	"math"
)

// IBytes returns s formatted as a binary-suffixed byte size, mirroring
// github.com/jonjohnsonjr/dagdotdev/pkg/humanize.IBytes.
func IBytes(s uint64) string {
	if s < 10 {
		return fmt.Sprintf("%d B", s)
	}
	const base = 1024
	sizes := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}

	e := math.Floor(math.Log(float64(s)) / math.Log(base))
	val := math.Floor(float64(s)/math.Pow(base, e)*10+0.5) / 10
	format := "%.0f %s"
	if val < 10 {
		format = "%.1f %s"
	}
	return fmt.Sprintf(format, val, sizes[int(e)])
}
