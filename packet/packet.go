// Package packet defines the packet structure for the Wisp protocol.
package packet

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// PacketType represents the type of a Wisp packet.
type PacketType uint8

// Packet type constants.
const (
	TypeConnect PacketType = iota + 1
	TypeData
	TypeContinue
	TypeClose
)

// StreamType represents the type of a stream (TCP or UDP).
type StreamType uint8

// Stream type constants.
const (
	StreamTypeTCP StreamType = iota + 1
	StreamTypeUDP
)

// CloseReason represents the reason for closing a stream.
type CloseReason uint8

// Close reason constants.
const (
	ReasonHostBlocked CloseReason = iota + 1
	ReasonConnThrottled
	ReasonUserClosed
	ReasonNetworkError
)

// WispPacket represents a single packet in the Wisp protocol.
type WispPacket struct {
	Type     PacketType
	StreamID uint32
	Payload  interface{}
}

// ConnectPayload is the payload for a CONNECT packet.
type ConnectPayload struct {
	StreamType StreamType
	Hostname   string
	Port       uint32
}

// DataPayload is the payload for a DATA packet.
type DataPayload struct {
	Data *WispBuffer
}

// ContinuePayload is the payload for a CONTINUE packet.
type ContinuePayload struct {
	BufferRemaining uint32
}

// ClosePayload is the payload for a CLOSE packet.
type ClosePayload struct {
	Reason CloseReason
}

// WispBuffer is a wrapper around bytes.Buffer for Wisp-specific operations.
type WispBuffer struct {
	*bytes.Buffer
}

// NewWispBuffer creates a new WispBuffer.
func NewWispBuffer(buf []byte) *WispBuffer {
	return &WispBuffer{bytes.NewBuffer(buf)}
}

// WriteString writes a string to the buffer with its length prefixed.
func (wb *WispBuffer) WriteString(s string) error {
	err := binary.Write(wb, binary.LittleEndian, uint32(len(s)))
	if err != nil {
		return err
	}
	_, err = wb.Buffer.WriteString(s)
	return err
}

// ReadString reads a length-prefixed string from the buffer.
func (wb *WispBuffer) ReadString() (string, error) {
	var length uint32
	err := binary.Read(wb, binary.LittleEndian, &length)
	if err != nil {
		return "", err
	}

	if wb.Len() < int(length) {
		return "", fmt.Errorf("not enough data in buffer")
	}

	strBytes := wb.Next(int(length))
	return string(strBytes), nil
}

// Serialize serializes a WispPacket into a byte buffer.
func (wp *WispPacket) Serialize() *WispBuffer {
	buffer := NewWispBuffer(nil)

	buffer.WriteByte(byte(wp.Type))
	binary.Write(buffer, binary.LittleEndian, wp.StreamID)

	switch wp.Type {
	case TypeConnect:
		payload := wp.Payload.(*ConnectPayload)
		buffer.WriteByte(byte(payload.StreamType))
		buffer.WriteString(payload.Hostname)
		binary.Write(buffer, binary.LittleEndian, payload.Port)

	case TypeData:
		payload := wp.Payload.(*DataPayload)
		buffer.Write(payload.Data.Bytes())

	case TypeContinue:
		payload := wp.Payload.(*ContinuePayload)
		binary.Write(buffer, binary.LittleEndian, payload.BufferRemaining)

	case TypeClose:
		payload := wp.Payload.(*ClosePayload)
		buffer.WriteByte(byte(payload.Reason))
	}

	return buffer
}

// ParsePacket parses a single WispPacket from a byte buffer.
func ParsePacket(data []byte) (*WispPacket, error) {
	buffer := bytes.NewBuffer(data)

	packetType, err := buffer.ReadByte()
	if err != nil {
		return nil, err
	}

	var streamID uint32
	err = binary.Read(buffer, binary.LittleEndian, &streamID)
	if err != nil {
		return nil, err
	}

	wp := &WispPacket{
		Type:     PacketType(packetType),
		StreamID: streamID,
	}

	switch wp.Type {
	case TypeConnect:
		streamType, err := buffer.ReadByte()
		if err != nil {
			return nil, err
		}

		hostname, err := NewWispBuffer(buffer.Bytes()).ReadString()
		if err != nil {
			return nil, err
		}

		var port uint32
		err = binary.Read(buffer, binary.LittleEndian, &port)
		if err != nil {
			return nil, err
		}

		wp.Payload = &ConnectPayload{
			StreamType: StreamType(streamType),
			Hostname:   hostname,
			Port:       port,
		}

	case TypeData:
		wp.Payload = &DataPayload{
			Data: NewWispBuffer(buffer.Bytes()),
		}

	case TypeContinue:
		var bufferRemaining uint32
		err = binary.Read(buffer, binary.LittleEndian, &bufferRemaining)
		if err != nil {
			return nil, err
		}
		wp.Payload = &ContinuePayload{
			BufferRemaining: bufferRemaining,
		}

	case TypeClose:
		reason, err := buffer.ReadByte()
		if err != nil {
			return nil, err
		}
		wp.Payload = &ClosePayload{
			Reason: CloseReason(reason),
		}
	}

	return wp, nil
}

// ParseAllPackets parses multiple WispPackets from a byte buffer.
func ParseAllPackets(data []byte) ([]*WispPacket, error) {
	var packets []*WispPacket
	buffer := bytes.NewBuffer(data)

	for buffer.Len() > 0 {
		packet, err := ParsePacket(buffer.Bytes())
		if err != nil {
			return nil, err
		}
		packets = append(packets, packet)
		buffer.Next(len(packet.Serialize().Bytes()))
	}

	return packets, nil
}
