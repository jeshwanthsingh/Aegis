package main

import (
	"context"
	"errors"
	"log"
	"os"

	"aegis/internal/mcp"
)

var version = "dev"

func main() {
	logger := log.New(os.Stderr, "aegis-mcp: ", log.LstdFlags)
	server := mcp.NewServer(mcp.NewToolHandler(version), logger)
	if err := server.Serve(context.Background(), os.Stdin, os.Stdout); err != nil && !errors.Is(err, context.Canceled) {
		logger.Printf("server stopped: %v", err)
		os.Exit(1)
	}
}
