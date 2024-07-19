package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"

	"wisp-server-go/http"
	"wisp-server-go/options"
)

func main() {
	if err := options.LoadOptions(); err != nil {
		log.Fatalf("Failed to load options: %v", err)
	}

	http.StartServer()

	// Graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	fmt.Println("Shutting down...")
}