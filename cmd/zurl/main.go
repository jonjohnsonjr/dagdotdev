package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"

	"github.com/jonjohnsonjr/dagdotdev/pkg/forks/github.com/google/go-containerregistry/pkg/authn"
	"github.com/jonjohnsonjr/dagdotdev/pkg/forks/github.com/google/go-containerregistry/pkg/name"
	"github.com/jonjohnsonjr/dagdotdev/pkg/forks/github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/jonjohnsonjr/dagdotdev/internal/forks/compress/flate"
	"github.com/jonjohnsonjr/dagdotdev/internal/soci"
	"github.com/spf13/cobra"
)

func zurl() *cobra.Command {
	cmd := &cobra.Command{
		Use: "zurl",
	}

	cmd.AddCommand(cat())

	return cmd
}

func run(ctx context.Context, src, checkpoint string, start, end int64) error {
	ref, err := name.NewDigest(src)
	if err != nil {
		return fmt.Errorf("NewDigest(): %w", err)
	}

	opts := []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain)}
	blob := remote.LazyBlob(ref, "", nil, opts...)

	if checkpoint[0] == '"' {
		checkpoint, err = strconv.Unquote(checkpoint)
		if err != nil {
			return err
		}
	}
	from := flate.Checkpoint{}
	if err := json.Unmarshal([]byte(checkpoint), &from); err != nil {
		return err
	}

	rc, err := soci.ExtractCheckpoint(ctx, &from, blob, start, end)
	if err != nil {
		return err
	}
	defer rc.Close()

	if _, err := io.Copy(os.Stdout, rc); err != nil {
		return err
	}

	return nil
}

func cat() *cobra.Command {
	var (
		checkpoint string
		start      int64
		end        int64
	)
	cmd := &cobra.Command{
		Use:   "cat LAYER -f FILE --offset OFFSET --range RANGE --size SIZE",
		Short: "Read a blob from the registry by using seekable gzip",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			return run(ctx, args[0], checkpoint, start, end)
		},
	}

	cmd.Flags().Int64Var(&start, "start", 0, "Where file starts in uncompressed stream")
	cmd.Flags().Int64Var(&end, "end", 0, "Where file ends in uncompressed stream")
	cmd.Flags().StringVar(&checkpoint, "checkpoint", "", "Checkpoint JSON")

	return cmd
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := zurl().ExecuteContext(ctx); err != nil {
		cancel()
		os.Exit(1)
	}
}
