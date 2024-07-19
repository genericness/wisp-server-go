package packet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
)

// Packet type constants.
const (
	ConnectPayloadType uint8 = 1
	DataPayloadType    uint8 = 2
	ContinuePayloadType uint8 = 3
	ClosePayloadType   uint8 = 4

	StreamTypeTCP uint8 = 1
	StreamTypeUDP uint8 = 2
)

// Close reason constants.
const (
	CloseReasonVoluntary      uint8 = 1
	CloseReasonHostUnreachable uint8 = 2
	CloseReasonHostBlocked    uint8 = 3
	CloseReasonConnThrottled  uint8 = 4
	CloseReasonNetworkError   uint8 = 5
)

// WispBuffer represents a buffer for WISP packets.
type WispBuffer struct {
	*bytes.Buffer
}

// NewWispBuffer creates a new WispBuffer with the given data.
func NewWispBuffer(data []byte) *WispBuffer {
	return &WispBuffer{bytes.NewBuffer(data)}
}

// WriteUint8 writes a uint8 value to the buffer.
func (wb *WispBuffer) WriteUint8(value uint8) {
	wb.WriteByte(value)
}

// WriteUint16 writes a uint16 value to the buffer.
func (wb *WispBuffer) WriteUint16(value uint16) {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, value)
	wb.Write(data)
}

// WriteUint32 writes a uint32 value to the buffer.
func (wb *WispBuffer) WriteUint32(value uint32) {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, value)
	wb.Write(data)
}

// WriteString writes a string value to the buffer.
func (wb *WispBuffer) WriteString(value string) {
	wb.WriteUint16(uint16(len(value)))
	wb.WriteString(value)
}

// ReadUint8 reads a uint8 value from the buffer.
func (wb *WispBuffer) ReadUint8() (uint8, error) {
	value, err := wb.ReadByte()
	return uint8(value), err
}

// ReadUint16 reads a uint16 value from the buffer.
func (wb *WispBuffer) ReadUint16() (uint16, error) {
	data, err := ReadBytes(wb.Buffer, 2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(data), nil
}

// ReadUint32 reads a uint32 value from the buffer.
func (wb *WispBuffer) ReadUint32() (uint32, error) {
	data, err := ReadBytes(wb.Buffer, 4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(data), nil
}

// ReadString reads a string value from the buffer.
func (wb *WispBuffer) ReadString() (string, error) {
	length, err := wb.ReadUint16()
	if err != nil {
		return "", err
	}

	data, err := ReadBytes(wb.Buffer, int(length))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// WispPacket represents a WISP packet.
type WispPacket struct {
	Type        uint8
	StreamID   uint16
	PayloadSize uint32
	Payload     interface{}
}

// Serialize serializes the packet into a buffer.
func (wp *WispPacket) Serialize() *WispBuffer {
	payloadBuffer := &WispBuffer{new(bytes.Buffer)}
	switch p := wp.Payload.(type) {
	case *ConnectPayload:
		payloadBuffer.WriteUint8(p.StreamType)
		payloadBuffer.WriteString(p.Hostname)
		payloadBuffer.WriteUint16(p.Port)
	case *DataPayload:
		payloadBuffer.Write(p.Data.Bytes())
	case *ContinuePayload:
		payloadBuffer.WriteUint32(p.BufferRemaining)
	case *ClosePayload:
		payloadBuffer.WriteUint8(p.Reason)
	default:
		panic(fmt.Sprintf("unknown payload type: %T", wp.Payload))
	}

	wp.PayloadSize = uint32(payloadBuffer.Len())

	buffer := &WispBuffer{new(bytes.Buffer)}
	buffer.WriteUint8(wp.Type)
	buffer.WriteUint16(wp.StreamID)
	buffer.WriteUint32(wp.PayloadSize)
	buffer.Write(payloadBuffer.Bytes())

	return buffer
}

// ParsePacket parses a packet from a buffer.
func ParsePacket(buffer *WispBuffer) (*WispPacket, error) {
	packetType, err := buffer.ReadUint8()
	if err != nil {
		return nil, fmt.Errorf("failed to read packet type: %w", err)
	}

	streamID, err := buffer.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("failed to read stream ID: %w", err)
	}

	payloadSize, err := buffer.ReadUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read payload size: %w", err)
	}

	if uint32(buffer.Len()) < payloadSize {
		return nil, fmt.Errorf("incomplete packet: expected payload size %d, but only have %d bytes", payloadSize, buffer.Len())
	}

	var payload interface{}
	switch packetType {
	case ConnectPayloadType:
		streamType, err := buffer.ReadUint8()
		if err != nil {
			return nil, fmt.Errorf("failed to read stream type: %w", err)
		}

		hostname, err := buffer.ReadString()
		if err != nil {
			return nil, fmt.Errorf("failed to read hostname: %w", err)
		}

		port, err := buffer.ReadUint16()
		if err != nil {
			return nil, fmt.Errorf("failed to read port: %w", err)
		}

		payload = &ConnectPayload{
			StreamType: streamType,
			Hostname:   hostname,
			Port:       port,
		}

	case DataPayloadType:
		data, err := ReadBytes(buffer.Buffer, int(payloadSize))
		if err != nil {
			return nil, fmt.Errorf("failed to read data payload: %w", err)
		}

		payload = &DataPayload{
			Data: NewWispBuffer(data),
		}

	case ContinuePayloadType:
		bufferRemaining, err := buffer.ReadUint32()
		if err != nil {
			return nil, fmt.Errorf("failed to read buffer remaining: %w", err)
		}

		payload = &ContinuePayload{
			BufferRemaining: bufferRemaining,
		}

	case ClosePayloadType:
		reason, err := buffer.ReadUint8()
		if err != nil {
			return nil, fmt.Errorf("failed to read close reason: %w", err)
		}

		payload = &ClosePayload{
			Reason: reason,
		}

	default:
		return nil, fmt.Errorf("unknown packet type: %d", packetType)
	}

	return &WispPacket{
		Type:        packetType,
		StreamID:   streamID,
		PayloadSize: payloadSize,
		Payload:     payload,
	}, nil
}

// ParseAllPackets parses all packets from a byte slice.
func ParseAllPackets(data []byte) ([]*WispPacket, error) {
	var packets []*WispPacket
	buffer := NewWispBuffer(data)

	for buffer.Len() > 0 {
		packet, err := ParsePacket(buffer)
		if err != nil {
			return nil, err
		}
		packets = append(packets, packet)
	}

	return packets, nil
}

// ConnectPayload represents a connect packet payload.
type ConnectPayload struct {
	StreamType uint8
	Hostname   string
	Port       uint16
}

// DataPayload represents a data packet payload.
type DataPayload struct {
	Data *WispBuffer
}

// ContinuePayload represents a continue packet payload.
type ContinuePayload struct {
	BufferRemaining uint32
}

// ClosePayload represents a close packet payload.
type ClosePayload struct {
	Reason uint8
}

// SplitBytes splits a byte slice into smaller slices of a maximum size.
func SplitBytes(data []byte, maxSize int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(data); i += maxSize {
		end := int(math.Min(float64(i+maxSize), float64(len(data))))
		chunks = append(chunks, data[i:end])
	}
	return chunks
}

// ReadBytes reads a specified number of bytes from a bytes.Buffer.
func ReadBytes(buffer *bytes.Buffer, length int) ([]byte, error) {
	if length > buffer.Len() {
		return nil, fmt.Errorf("not enough bytes in buffer")
	}
	data := buffer.Next(length)
	return data, nil
}