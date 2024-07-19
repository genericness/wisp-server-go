package http

import (
	"fmt"
	"net/http"

	"wisp-server-go/connection"
	"wisp-server-go/logging"
	"wisp-server-go/websocket"
)

func StartServer() {
	http.HandleFunc("/", handleWebSocket)

	go func() {
		port := ":8080"
		logging.Info(fmt.Sprintf("Server listening on %s", port))
		if err := http.ListenAndServe(port, nil); err != nil {
			logging.Error(fmt.Sprintf("Error starting server: %v", err))
		}
	}()
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	logging.Info(fmt.Sprintf("New connection from %s", r.RemoteAddr))

	ws, err := websocket.NewAsyncWebSocket(w, r)
	if err != nil {
		logging.Error(fmt.Sprintf("Error upgrading to websocket: %v", err))
		return
	}

	conn := connection.NewServerConnection(ws, r.URL.Path)
	if err := conn.Setup(); err != nil {
		logging.Error(fmt.Sprintf("Error setting up connection: %v", err))
		return
	}

	if err := conn.Run(); err != nil {
		logging.Error(fmt.Sprintf("Error running connection: %v", err))
	}

	logging.Info(fmt.Sprintf("Connection closed from %s", r.RemoteAddr))
}