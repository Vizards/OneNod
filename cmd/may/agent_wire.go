package main

import (
	"encoding/binary"
	"io"
)

type wireReader struct {
	offset int
	value  []byte
}

func (reader *wireReader) byte() (byte, error) {
	if reader.offset >= len(reader.value) {
		return 0, io.ErrUnexpectedEOF
	}
	value := reader.value[reader.offset]
	reader.offset++
	return value, nil
}

func (reader *wireReader) uint32() (uint32, error) {
	if reader.offset+4 > len(reader.value) {
		return 0, io.ErrUnexpectedEOF
	}
	value := binary.BigEndian.Uint32(reader.value[reader.offset : reader.offset+4])
	reader.offset += 4
	return value, nil
}

func (reader *wireReader) string() ([]byte, error) {
	length, err := reader.uint32()
	if err != nil || uint64(length) > uint64(len(reader.value)-reader.offset) {
		return nil, io.ErrUnexpectedEOF
	}
	value := reader.value[reader.offset : reader.offset+int(length)]
	reader.offset += int(length)
	return value, nil
}

func (reader *wireReader) done() bool { return reader.offset == len(reader.value) }

func writeWireString(writer io.Writer, value []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}
