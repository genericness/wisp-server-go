package websocket

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"wisp-server-go/logging"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for now
	},
}

// AsyncWebSocket provides an asynchronous wrapper for websocket connections.
type AsyncWebSocket struct {
	conn    *websocket.Conn
	send    chan []byte
	receive chan []byte
	close   chan struct{}
	once    sync.Once
}

// NewAsyncWebSocket creates a new AsyncWebSocket.
func NewAsyncWebSocket(w http.ResponseWriter, r *http.Request) (*AsyncWebSocket, error) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, err
	}

	aws := &AsyncWebSocket{
		conn:    conn,
		send:    make(chan []byte, 1024),
		receive: make(chan []byte, 1024),
		close:   make(chan struct{}),
	}

	go aws.readLoop()
	go aws.writeLoop()

	return aws, nil
}

// Send sends data over the websocket connection.
func (aws *AsyncWebSocket) Send(data []byte) error {
	select {
	case aws.send <- data:
		return nil
	case <-aws.close:
		return fmt.Errorf("websocket closed")
	}
}

// Receive receives data from the websocket connection.
func (aws *AsyncWebSocket) Receive() ([]byte, error) {
	select {
	case data := <-aws.receive:
		return data, nil
	case <-aws.close:
		return nil, fmt.Errorf("websocket closed")
	}
}

// Close closes the websocket connection.
func (aws *AsyncWebSocket) Close() error {
	aws.once.Do(func() {
		close(aws.close)
		aws.conn.Close()
	})
	return nil
}

// readLoop handles reading messages from the websocket connection.
func (aws *AsyncWebSocket) readLoop() {
	defer aws.Close()

	for {
		messageType, data, err := aws.conn.ReadMessage()
		if err != nil {
			logging.Warn(fmt.Sprintf("Error reading websocket message: %v", err)) // Format error
			return
		}

		if messageType == websocket.CloseMessage {
			logging.Debug("Received websocket close message")
			return
		}

		select {
		case aws.receive <- data:
		case <-aws.close:
			return
		}
	}
}

// writeLoop handles writing messages to the websocket connection.
func (aws *AsyncWebSocket) writeLoop() {
	defer aws.Close()

	for {
		select {
		case data := <-aws.send:
			err := aws.conn.WriteMessage(websocket.BinaryMessage, data)
			if err != nil {
				logging.Warn(fmt.Sprintf("Error writing websocket message: %v", err)) // Format error
				return
			}
		case <-aws.close:
			return
		}
	}
}

// SetReadDeadline sets the read deadline for the websocket connection.
func (aws *AsyncWebSocket) SetReadDeadline(t time.Time) error {
	return aws.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline for the websocket connection.
func (aws *AsyncWebSocket) SetWriteDeadline(t time.Time) error {
	return aws.conn.SetWriteDeadline(t)
}

// GetConnID generates a unique connection ID.
func GetConnID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// AsyncQueue provides an asynchronous queue for data.
type AsyncQueue struct {
	queue       [][]byte
	maxSize     int
	cond        *sync.Cond
	closed      bool
	closeSignal chan struct{}
}

// NewAsyncQueue creates a new AsyncQueue.
func NewAsyncQueue(maxSize int) *AsyncQueue {
	return &AsyncQueue{
		queue:       make([][]byte, 0, maxSize),
		maxSize:     maxSize,
		cond:        sync.NewCond(&sync.Mutex{}),
		closed:      false,
		closeSignal: make(chan struct{}),
	}
}

// Put adds data to the queue.
func (q *AsyncQueue) Put(data []byte) {
	q.cond.L.Lock()
	defer q.cond.L.Unlock()

	for len(q.queue) >= q.maxSize && !q.closed {
		q.cond.Wait()
	}

	if q.closed {
		return
	}

	q.queue = append(q.queue, data)
	q.cond.Signal()
}

// Get retrieves data from the queue.
func (q *AsyncQueue) Get() ([]byte, error) {
	q.cond.L.Lock()
	defer q.cond.L.Unlock()

	for len(q.queue) == 0 && !q.closed {
		q.cond.Wait()
	}

	if q.closed {
		return nil, fmt.Errorf("queue closed")
	}

	data := q.queue[0]
	q.queue = q.queue[1:]
	q.cond.Signal()
	return data, nil
}

// Close closes the queue.
func (q *AsyncQueue) Close() {
	q.cond.L.Lock()
	defer q.cond.L.Unlock()

	if !q.closed {
		q.closed = true
		close(q.closeSignal)
		q.cond.Broadcast()
	}
}

// Size returns the current size of the queue.
func (q *AsyncQueue) Size() int {
	q.cond.L.Lock()
	defer q.cond.L.Unlock()
	return len(q.queue)
}

// WaitForClose waits for the queue to be closed.
func (q *AsyncQueue) WaitForClose() {
	<-q.closeSignal
}