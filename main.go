package main

import (
	"context"
	"fmt"
	"os"

	plugin "github.com/concord-dev/concord/pkg/plugin"
)

func main() {
	c, err := newCollector(context.Background(), os.Getenv("AWS_REGION"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws plugin: %v\n", err)
		os.Exit(2)
	}
	plugin.Serve(c)
}
