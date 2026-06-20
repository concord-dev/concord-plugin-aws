// Command concord-plugin-aws serves the AWS Concord collector over protocol v1.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/concord-dev/concord-plugin-aws/internal/aws"
	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

func main() {
	c, err := aws.New(context.Background(), os.Getenv("AWS_REGION"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws plugin: %v\n", err)
		os.Exit(2)
	}
	plugin.Serve(c)
}
