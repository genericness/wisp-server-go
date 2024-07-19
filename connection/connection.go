package connection

import (
	"fmt"
	"net"
	"sync"
	"time"

	"wisp-server-go/filter"
	"wisp-server-go/logging"
	"wisp-server-go/packet"
	"wisp-server-go/websocket"
)

type ServerStream struct {
	StreamID   uint16
	Conn       *ServerConnection
	Socket     net.Conn
	SendBuffer *websocket.AsyncQueue
	PacketsSent int
	sync.Mutex
}

func NewServerStream(streamID uint16, conn *ServerConnection, socket net.Conn) *ServerStream {
	return &ServerStream{
		StreamID:   streamID,
		Conn:       conn,
		Socket:     socket,
		SendBuffer: websocket.NewAsyncQueue(128),
		PacketsSent: 0,
	}
}

func (ss *ServerStream) Setup() error {
	go ss.tcpToWS()
	go ss.wsToTCP()
	return nil
}

func (ss *ServerStream) tcpToWS() {
	defer ss.Close()

	for {
		buffer := make([]byte, 1024)
		n, err := ss.Socket.Read(buffer)
		if err != nil {
			logging.Error(fmt.Sprintf("(%s) Error reading from TCP/UDP socket: %v", ss.Conn.ConnID, err))
			return
		}

		dataPacket := &packet.WispPacket{
			Type:      packet.TypeData,
			StreamID: ss.StreamID,
			Payload: &packet.DataPayload{
				Data: packet.NewWispBuffer(buffer[:n]),
			},
		}

		packetData := dataPacket.Serialize().Bytes()
		err = ss.Conn.WS.Send(packetData)
		if err != nil {
			logging.Error(fmt.Sprintf("(%s) Error sending data packet: %v", ss.Conn.ConnID, err))
			return
		}
	}
}

func (ss *ServerStream) wsToTCP() {
	defer ss.Close()

	for {
		data, err := ss.SendBuffer.Get()
		if err != nil {
			logging.Error(fmt.Sprintf("(%s) Error getting data from send buffer: %v", ss.Conn.ConnID, err))
			return
		}

		_, err = ss.Socket.Write(data)
		if err != nil {
			logging.Error(fmt.Sprintf("(%s) Error writing to TCP/UDP socket: %v", ss.Conn.ConnID, err))
			return
		}

		ss.PacketsSent++
		if ss.PacketsSent%(64) == 0 {
			continuePacket := &packet.WispPacket{
				Type:      packet.TypeContinue,
				StreamID: ss.StreamID,
				Payload: &packet.ContinuePayload{
					BufferRemaining: uint32(ss.SendBuffer.Capacity() - ss.SendBuffer.Size()), // Use Capacity() instead of maxSize
				},
			}

			packetData := continuePacket.Serialize().Bytes()
			err = ss.Conn.WS.Send(packetData)
			if err != nil {
				logging.Error(fmt.Sprintf("(%s) Error sending continue packet: %v", ss.Conn.ConnID, err))
				return
			}
		}
	}
}

func (ss *ServerStream) Close() error {
	ss.SendBuffer.Close()
	return ss.Socket.Close()
}

func (ss *ServerStream) PutData(data []byte) error {
	ss.SendBuffer.Put(data)
	return nil
}

type ServerConnection struct {
	WS      *websocket.AsyncWebSocket
	Path    string
	Streams map[uint16]*ServerStream
	ConnID  string
	sync.Mutex
}

func NewServerConnection(ws *websocket.AsyncWebSocket, path string) *ServerConnection {
	return &ServerConnection{
		WS:      ws,
		Path:    path,
		Streams: make(map[uint16]*ServerStream),
		ConnID:  websocket.GetConnID(),
	}
}

func (sc *ServerConnection) Setup() error {
	logging.Info(fmt.Sprintf("Setting up new WISP connection with ID %s", sc.ConnID))

	initialContinuePacket := &packet.WispPacket{
		Type:      packet.TypeContinue,
		StreamID: 0,
		Payload: &packet.ContinuePayload{
			BufferRemaining: 128,
		},
	}

	packetData := initialContinuePacket.Serialize().Bytes()
	err := sc.WS.Send(packetData)
	if err != nil {
		return fmt.Errorf("failed to send initial continue packet: %w", err)
	}

	return nil
}

func (sc *ServerConnection) CreateStream(streamID uint16, streamType uint8, hostname string, port uint16) error {
	sc.Lock()
	defer sc.Unlock()

	if _, exists := sc.Streams[streamID]; exists {
		return fmt.Errorf("stream with ID %d already exists", streamID)
	}

	// Create StreamInfo and populate it
	streamInfo := filter.StreamInfo{
		StreamType:  streamType,
		Hostname:    hostname,
		Port:        port,
		StreamCount: len(sc.Streams), // Pass the total stream count
	}

	closeReason := filter.IsStreamAllowed(streamInfo) // Assuming IsStreamAllowed takes only StreamInfo
	if closeReason != 0 {
		logging.Warn(fmt.Sprintf("(%s) Refusing to create a stream to %s:%d", sc.ConnID, hostname, port))
		closePacket := &packet.WispPacket{
			Type:      packet.TypeClose,
			StreamID: streamID,
			Payload: &packet.ClosePayload{
				Reason: closeReason,
			},
		}

		packetData := closePacket.Serialize().Bytes()
		if err := sc.WS.Send(packetData); err != nil {
			return fmt.Errorf("failed to send close packet: %w", err)
		}
		return nil
	}

	var socket net.Conn
	var err error

	if streamType == packet.StreamTypeTCP {
		socket, err = net.Dial("tcp", fmt.Sprintf("%s:%d", hostname, port))
	} else if streamType == packet.StreamTypeUDP {
		socket, err = net.Dial("udp", fmt.Sprintf("%s:%d", hostname, port))
	} else {
		return fmt.Errorf("invalid stream type: %d", streamType)
	}

	if err != nil {
		return fmt.Errorf("failed to dial %s:%d: %w", hostname, port, err)
	}

	stream := NewServerStream(streamID, sc, socket)
	sc.Streams[streamID] = stream

	go func() {
		err := stream.Setup()
		if err != nil {
			logging.Error(fmt.Sprintf("(%s) Error setting up stream: %v", sc.ConnID, err))
			sc.CloseStream(streamID, packet.ReasonNetworkError) // Use ReasonNetworkError
		}
	}()

	return nil
}

func (sc *ServerConnection) CloseStream(streamID uint16, reason uint8) error {
	sc.Lock()
	defer sc.Unlock()

	stream, exists := sc.Streams[streamID]
	if !exists {
		return fmt.Errorf("stream with ID %d does not exist", streamID)
	}

	if reason != 0 {
		logging.Info(fmt.Sprintf("(%s) Closing stream to %s for reason %d", sc.ConnID, stream.Socket.RemoteAddr(), reason))
	}

	delete(sc.Streams, streamID)
	return stream.Close()
}

func (sc *ServerConnection) RoutePacket(data []byte) error {
	packets, err := packet.ParseAllPackets(data)
	if err != nil {
		return fmt.Errorf("failed to parse packet: %w", err)
	}

	for _, packet := range packets {
		switch packet.Type {
		case packet.TypeConnect:
			payload := packet.Payload.(*packet.ConnectPayload)
			logging.Info(fmt.Sprintf("(%s) Opening new stream to %s:%d", sc.ConnID, payload.Hostname, payload.Port))
			err := sc.CreateStream(packet.StreamID, payload.StreamType, payload.Hostname, payload.Port)
			if err != nil {
				logging.Error(fmt.Sprintf("(%s) Error creating stream: %v", sc.ConnID, err))
				sc.CloseStream(packet.StreamID, packet.ReasonNetworkError) // Use ReasonNetworkError
			}

		case packet.TypeData:
			sc.Lock()
			stream, exists := sc.Streams[packet.StreamID]
			sc.Unlock()
			if !exists {
				logging.Warn(fmt.Sprintf("(%s) Received a DATA packet for a stream which doesn't exist", sc.ConnID))
				continue
			}
			payload := packet.Payload.(*packet.DataPayload)
			stream.PutData(payload.Data.Bytes())

		case packet.TypeContinue:
			logging.Warn(fmt.Sprintf("(%s) Client sent a CONTINUE packet, this should never be possible", sc.ConnID))

		case packet.TypeClose:
			sc.CloseStream(packet.StreamID, packet.Payload.(*packet.ClosePayload).Reason)

		default:
			logging.Warn(fmt.Sprintf("(%s) Unknown packet type: %d", sc.ConnID, packet.Type))
		}
	}

	return nil
}

func (sc *ServerConnection) Run() error {
	defer sc.WS.Close()
        // Heartbeat to keep the connection alive
	go func() {
		for {
			time.Sleep(30 * time.Second)
			err := sc.WS.Send([]byte{})
			if err != nil {
				logging.Error(fmt.Sprintf("(%s) Error sending heartbeat: %v", sc.ConnID, err))
				return
			}
		}
	}()

	for {
		data, err := sc.WS.Receive()
		if err != nil {
			logging.Error(fmt.Sprintf("(%s) Error receiving data: %v", sc.ConnID, err))
			return err
		}

		err = sc.RoutePacket(data)
		if err != nil {
			logging.Warn(fmt.Sprintf("(%s) Error routing packet: %v", sc.ConnID, err))
		}
	}
}