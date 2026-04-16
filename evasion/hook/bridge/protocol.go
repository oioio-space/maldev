package bridge

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	msgCall      byte = 0x01
	msgDecision  byte = 0x02
	msgLog       byte = 0x03
	msgExfil     byte = 0x04
	msgHeartbeat byte = 0x05
	msgRet       byte = 0x06
	msgCommand   byte = 0x07
	msgResponse  byte = 0x08
)

// writeFrameWithID writes a multiplexed frame: [length][msgType][reqID][payload].
// reqID = 0 is reserved for fire-and-forget messages (backward compat).
func writeFrameWithID(w io.Writer, msgType byte, reqID uint32, payload []byte) error {
	length := uint32(1 + 4 + len(payload))
	if err := binary.Write(w, binary.LittleEndian, length); err != nil {
		return fmt.Errorf("write frame length: %w", err)
	}
	if _, err := w.Write([]byte{msgType}); err != nil {
		return fmt.Errorf("write msg type: %w", err)
	}
	if err := binary.Write(w, binary.LittleEndian, reqID); err != nil {
		return fmt.Errorf("write req ID: %w", err)
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return fmt.Errorf("write payload: %w", err)
		}
	}
	return nil
}

// readFrameWithID reads a multiplexed frame. If the frame contains a reqID
// (length >= 5 after msgType), it is extracted. Legacy frames (no reqID)
// return reqID=0.
func readFrameWithID(r io.Reader) (msgType byte, reqID uint32, payload []byte, err error) {
	var length uint32
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return 0, 0, nil, fmt.Errorf("read frame length: %w", err)
	}
	if length < 1 {
		return 0, 0, nil, fmt.Errorf("frame too short")
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, 0, nil, fmt.Errorf("read frame body: %w", err)
	}
	msgType = buf[0]
	// V2 frame: [msgType][reqID(4)][payload]
	if len(buf) >= 5 {
		reqID = binary.LittleEndian.Uint32(buf[1:5])
		return msgType, reqID, buf[5:], nil
	}
	// Legacy frame: [msgType][payload] — no reqID
	return msgType, 0, buf[1:], nil
}

func writeFrame(w io.Writer, msgType byte, payload []byte) error {
	length := uint32(1 + len(payload))
	if err := binary.Write(w, binary.LittleEndian, length); err != nil {
		return fmt.Errorf("write frame length: %w", err)
	}
	if _, err := w.Write([]byte{msgType}); err != nil {
		return fmt.Errorf("write msg type: %w", err)
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return fmt.Errorf("write payload: %w", err)
		}
	}
	return nil
}

func readFrame(r io.Reader) (byte, []byte, error) {
	var length uint32
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return 0, nil, fmt.Errorf("read frame length: %w", err)
	}
	if length < 1 {
		return 0, nil, fmt.Errorf("frame too short")
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, fmt.Errorf("read frame body: %w", err)
	}
	return buf[0], buf[1:], nil
}

func encodeArgs(args [18]uintptr) []byte {
	buf := make([]byte, 18*8)
	for i, a := range args {
		binary.LittleEndian.PutUint64(buf[i*8:], uint64(a))
	}
	return buf
}

func decodeArgs(data []byte) [18]uintptr {
	var args [18]uintptr
	for i := 0; i < 18 && (i+1)*8 <= len(data); i++ {
		args[i] = uintptr(binary.LittleEndian.Uint64(data[i*8:]))
	}
	return args
}

func splitTagData(payload []byte) (string, []byte) {
	for i, b := range payload {
		if b == 0 {
			return string(payload[:i]), payload[i+1:]
		}
	}
	return string(payload), nil
}
