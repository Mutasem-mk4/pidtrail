package main

import (
	"context"
	"os"

	"github.com/pidtrail/pidtrail/internal/cli"
)

func main() {
	os.Exit(cli.Run(context.Background(), os.Args[1:]))
}
