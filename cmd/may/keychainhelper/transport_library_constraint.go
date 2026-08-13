package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"os"
)

const (
	transportMachO64HeaderSize   = 32
	transportLoadCommandSize     = 8
	transportLinkeditCommandSize = 16

	transportMachO64Magic                = 0xfeedfacf
	transportCPUTypeAMD64                = 0x01000007
	transportCPUTypeARM64                = 0x0100000c
	transportLCCodeSignature             = 0x1d
	transportSuperBlobMagic              = 0xfade0cc0
	transportCodeDirectoryMagic          = 0xfade0c02
	transportConstraintMagic             = 0xfade8181
	transportPrimaryCodeDirectorySlot    = 0
	transportConstraintSlot              = 11
	transportAlternateCodeDirectoryFirst = 0x1000
	transportAlternateCodeDirectoryLimit = 0x1005
	transportSuperBlobHeader             = 12
	transportSuperBlobIndex              = 8
	transportGenericBlobHeader           = 8
	transportCodeDirectoryBaseSize       = 44

	transportCodeDirectoryVersionBase     = 0x20001
	transportCodeDirectoryVersionScatter  = 0x20100
	transportCodeDirectoryVersionTeam     = 0x20200
	transportCodeDirectoryVersionLimit64  = 0x20300
	transportCodeDirectoryVersionExecSeg  = 0x20400
	transportCodeDirectoryVersionRuntime  = 0x20500
	transportCodeDirectorySHA256          = 2
	transportCodeDirectorySHA256Size      = sha256.Size
	transportCodeDirectoryCDHashSize      = 20
	transportLibraryConstraintSpecialSlot = 11

	transportIndexChunkEntries = 512
)

type transportParsedCodeDirectory struct {
	hashOffset    uint64
	nSpecialSlots uint64
	hashSize      uint64
}

// transportLibraryConstraintBlob returns the exact embedded library-load
// constraint blob from a thin arm64 or amd64 Mach-O only when the unique
// primary CodeDirectory both matches the CDHash selected by Security.framework
// and seals that exact blob in special slot -11. The returned bytes include the
// blob magic and length. A valid legacy code signature without the constraint
// SuperBlob slot returns nil, nil.
//
// The parser uses only ReaderAt operations so inspection never depends on, or
// mutates, the inherited descriptor's current file position.
func transportLibraryConstraintBlob(file *os.File, expectedCDHash []byte) ([]byte, error) {
	if file == nil {
		return nil, errors.New("transport library constraint file is unavailable")
	}
	if len(expectedCDHash) != transportCodeDirectoryCDHashSize {
		return nil, errors.New("transport library constraint expected CDHash is invalid")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 ||
		info.Size() > maximumTransportBinarySize {
		return nil, errors.New("transport library constraint file is invalid")
	}
	fileSize := uint64(info.Size())

	var header [transportMachO64HeaderSize]byte
	if err := readTransportConstraintAt(file, 0, header[:]); err != nil {
		return nil, errors.New("transport library constraint Mach-O header is invalid")
	}
	if binary.LittleEndian.Uint32(header[0:4]) != transportMachO64Magic {
		return nil, errors.New("transport library constraint requires a thin 64-bit Mach-O")
	}
	cpuType := binary.LittleEndian.Uint32(header[4:8])
	if cpuType != transportCPUTypeARM64 && cpuType != transportCPUTypeAMD64 {
		return nil, errors.New("transport library constraint Mach-O architecture is unsupported")
	}

	commandCount := uint64(binary.LittleEndian.Uint32(header[16:20]))
	commandBytes := uint64(binary.LittleEndian.Uint32(header[20:24]))
	commandStart := uint64(transportMachO64HeaderSize)
	if commandCount*uint64(transportLoadCommandSize) > commandBytes ||
		!transportConstraintRangeWithin(commandStart, commandBytes, fileSize) {
		return nil, errors.New("transport library constraint load commands are invalid")
	}
	commandEnd := commandStart + commandBytes
	commandOffset := commandStart
	codeSignatureCount := 0
	var codeSignatureOffset, codeSignatureSize uint64

	for index := uint64(0); index < commandCount; index++ {
		var commandHeader [transportLoadCommandSize]byte
		if !transportConstraintRangeWithin(commandOffset, uint64(len(commandHeader)), commandEnd) ||
			readTransportConstraintAt(file, commandOffset, commandHeader[:]) != nil {
			return nil, errors.New("transport library constraint load command is invalid")
		}
		command := binary.LittleEndian.Uint32(commandHeader[0:4])
		commandSize := uint64(binary.LittleEndian.Uint32(commandHeader[4:8]))
		if commandSize < transportLoadCommandSize || commandSize%8 != 0 ||
			!transportConstraintRangeWithin(commandOffset, commandSize, commandEnd) {
			return nil, errors.New("transport library constraint load command is invalid")
		}
		if command == transportLCCodeSignature {
			codeSignatureCount++
			if codeSignatureCount != 1 || commandSize != transportLinkeditCommandSize {
				return nil, errors.New("transport library constraint code signature command is invalid")
			}
			var linkedit [transportLinkeditCommandSize - transportLoadCommandSize]byte
			if err := readTransportConstraintAt(
				file, commandOffset+transportLoadCommandSize, linkedit[:],
			); err != nil {
				return nil, errors.New("transport library constraint code signature command is invalid")
			}
			codeSignatureOffset = uint64(binary.LittleEndian.Uint32(linkedit[0:4]))
			codeSignatureSize = uint64(binary.LittleEndian.Uint32(linkedit[4:8]))
		}
		commandOffset += commandSize
	}
	if commandOffset != commandEnd || codeSignatureCount != 1 ||
		codeSignatureSize < transportSuperBlobHeader ||
		codeSignatureOffset < commandEnd ||
		!transportConstraintRangeWithin(codeSignatureOffset, codeSignatureSize, fileSize) {
		return nil, errors.New("transport library constraint code signature is invalid")
	}

	var superHeader [transportSuperBlobHeader]byte
	if err := readTransportConstraintAt(file, codeSignatureOffset, superHeader[:]); err != nil ||
		binary.BigEndian.Uint32(superHeader[0:4]) != transportSuperBlobMagic {
		return nil, errors.New("transport library constraint SuperBlob is invalid")
	}
	superBlobSize := uint64(binary.BigEndian.Uint32(superHeader[4:8]))
	indexCount := uint64(binary.BigEndian.Uint32(superHeader[8:12]))
	if superBlobSize < transportSuperBlobHeader || superBlobSize > codeSignatureSize {
		return nil, errors.New("transport library constraint SuperBlob length is invalid")
	}
	indexBytes := indexCount * uint64(transportSuperBlobIndex)
	indexStart := uint64(transportSuperBlobHeader)
	if !transportConstraintRangeWithin(indexStart, indexBytes, superBlobSize) {
		return nil, errors.New("transport library constraint SuperBlob index is invalid")
	}
	indexEnd := indexStart + indexBytes

	codeDirectoryFound := false
	constraintFound := false
	var codeDirectoryOffset, constraintOffset uint64
	var indexChunk [transportIndexChunkEntries * transportSuperBlobIndex]byte
	for first := uint64(0); first < indexCount; {
		entries := indexCount - first
		if entries > transportIndexChunkEntries {
			entries = transportIndexChunkEntries
		}
		chunkSize := entries * uint64(transportSuperBlobIndex)
		chunk := indexChunk[:int(chunkSize)]
		if err := readTransportConstraintAt(
			file,
			codeSignatureOffset+indexStart+first*uint64(transportSuperBlobIndex),
			chunk,
		); err != nil {
			return nil, errors.New("transport library constraint SuperBlob index is invalid")
		}
		for entry := uint64(0); entry < entries; entry++ {
			entryStart := int(entry * uint64(transportSuperBlobIndex))
			slotType := binary.BigEndian.Uint32(chunk[entryStart : entryStart+4])
			slotOffset := uint64(binary.BigEndian.Uint32(chunk[entryStart+4 : entryStart+8]))
			if slotOffset < indexEnd ||
				!transportConstraintRangeWithin(slotOffset, transportGenericBlobHeader, superBlobSize) {
				return nil, errors.New("transport library constraint SuperBlob slot offset is invalid")
			}
			switch {
			case slotType == transportPrimaryCodeDirectorySlot:
				if codeDirectoryFound {
					return nil, errors.New("transport library constraint SuperBlob has duplicate primary CodeDirectories")
				}
				codeDirectoryFound = true
				codeDirectoryOffset = slotOffset
			case slotType >= transportAlternateCodeDirectoryFirst &&
				slotType < transportAlternateCodeDirectoryLimit:
				return nil, errors.New("transport library constraint SuperBlob has alternate CodeDirectories")
			case slotType == transportConstraintSlot:
				if constraintFound {
					return nil, errors.New("transport library constraint SuperBlob has duplicate constraint slots")
				}
				constraintFound = true
				constraintOffset = slotOffset
			}
		}
		first += entries
	}
	if !codeDirectoryFound {
		return nil, errors.New("transport library constraint SuperBlob has no primary CodeDirectory")
	}

	codeDirectory, err := readTransportConstraintBlob(
		file, codeSignatureOffset, codeDirectoryOffset, superBlobSize,
		transportCodeDirectoryMagic,
	)
	if err != nil {
		return nil, errors.New("transport library constraint CodeDirectory is invalid")
	}
	parsedCodeDirectory, err := parseTransportCodeDirectory(codeDirectory, expectedCDHash)
	if err != nil {
		return nil, err
	}
	if !constraintFound {
		return nil, nil
	}

	constraint, err := readTransportConstraintBlob(
		file, codeSignatureOffset, constraintOffset, superBlobSize,
		transportConstraintMagic,
	)
	if err != nil {
		return nil, errors.New("transport library constraint blob is invalid")
	}
	if transportConstraintRangesOverlap(
		codeDirectoryOffset, uint64(len(codeDirectory)),
		constraintOffset, uint64(len(constraint)),
	) {
		return nil, errors.New("transport library constraint blobs overlap")
	}
	if err := verifyTransportLibraryConstraintSeal(
		codeDirectory, parsedCodeDirectory, constraint,
	); err != nil {
		return nil, err
	}
	return constraint, nil
}

func readTransportConstraintBlob(
	file *os.File,
	superBlobOffset uint64,
	blobOffset uint64,
	superBlobSize uint64,
	expectedMagic uint32,
) ([]byte, error) {
	var header [transportGenericBlobHeader]byte
	if !transportConstraintRangeWithin(blobOffset, uint64(len(header)), superBlobSize) ||
		readTransportConstraintAt(file, superBlobOffset+blobOffset, header[:]) != nil ||
		binary.BigEndian.Uint32(header[0:4]) != expectedMagic {
		return nil, errors.New("transport code-signing blob header is invalid")
	}
	blobSize := uint64(binary.BigEndian.Uint32(header[4:8]))
	if blobSize < transportGenericBlobHeader ||
		!transportConstraintRangeWithin(blobOffset, blobSize, superBlobSize) {
		return nil, errors.New("transport code-signing blob length is invalid")
	}
	blob := make([]byte, int(blobSize))
	if err := readTransportConstraintAt(file, superBlobOffset+blobOffset, blob); err != nil {
		return nil, errors.New("transport code-signing blob is truncated")
	}
	return blob, nil
}

func parseTransportCodeDirectory(
	codeDirectory []byte,
	expectedCDHash []byte,
) (transportParsedCodeDirectory, error) {
	invalid := func() (transportParsedCodeDirectory, error) {
		return transportParsedCodeDirectory{}, errors.New("transport library constraint CodeDirectory is invalid")
	}
	if len(codeDirectory) < transportCodeDirectoryBaseSize ||
		binary.BigEndian.Uint32(codeDirectory[0:4]) != transportCodeDirectoryMagic ||
		uint64(binary.BigEndian.Uint32(codeDirectory[4:8])) != uint64(len(codeDirectory)) ||
		len(expectedCDHash) != transportCodeDirectoryCDHashSize {
		return invalid()
	}
	version := binary.BigEndian.Uint32(codeDirectory[8:12])
	headerSize, ok := transportCodeDirectoryHeaderSize(version)
	if !ok || uint64(len(codeDirectory)) < headerSize {
		return invalid()
	}
	if binary.BigEndian.Uint32(codeDirectory[40:44]) != 0 {
		return invalid()
	}
	if version >= transportCodeDirectoryVersionScatter &&
		binary.BigEndian.Uint32(codeDirectory[44:48]) != 0 {
		return invalid()
	}
	if version >= transportCodeDirectoryVersionLimit64 &&
		binary.BigEndian.Uint32(codeDirectory[52:56]) != 0 {
		return invalid()
	}
	if version >= transportCodeDirectoryVersionRuntime &&
		binary.BigEndian.Uint32(codeDirectory[92:96]) != 0 {
		return invalid()
	}

	hashOffset := uint64(binary.BigEndian.Uint32(codeDirectory[16:20]))
	identifierOffset := uint64(binary.BigEndian.Uint32(codeDirectory[20:24]))
	nSpecialSlots := uint64(binary.BigEndian.Uint32(codeDirectory[24:28]))
	nCodeSlots := uint64(binary.BigEndian.Uint32(codeDirectory[28:32]))
	hashSize := uint64(codeDirectory[36])
	hashType := codeDirectory[37]
	pageSizeExponent := codeDirectory[39]
	if hashType != transportCodeDirectorySHA256 ||
		hashSize != transportCodeDirectorySHA256Size ||
		pageSizeExponent == 0 || pageSizeExponent > 31 {
		return invalid()
	}

	specialHashBytes := nSpecialSlots * hashSize
	codeHashBytes := nCodeSlots * hashSize
	codeDirectorySize := uint64(len(codeDirectory))
	if hashOffset < specialHashBytes ||
		hashOffset-specialHashBytes < headerSize ||
		!transportConstraintRangeWithin(hashOffset, codeHashBytes, codeDirectorySize) ||
		hashOffset+codeHashBytes != codeDirectorySize {
		return invalid()
	}
	specialHashStart := hashOffset - specialHashBytes
	if identifierOffset < headerSize || identifierOffset >= specialHashStart ||
		!transportCodeDirectoryStringTerminates(codeDirectory, identifierOffset, specialHashStart) {
		return invalid()
	}
	if version >= transportCodeDirectoryVersionTeam {
		teamOffset := uint64(binary.BigEndian.Uint32(codeDirectory[48:52]))
		if teamOffset != 0 && (teamOffset < headerSize || teamOffset >= specialHashStart ||
			!transportCodeDirectoryStringTerminates(codeDirectory, teamOffset, specialHashStart)) {
			return invalid()
		}
	}

	codeLimit := uint64(binary.BigEndian.Uint32(codeDirectory[32:36]))
	if version >= transportCodeDirectoryVersionLimit64 {
		codeLimit64 := binary.BigEndian.Uint64(codeDirectory[56:64])
		if codeLimit == uint64(^uint32(0)) {
			if codeLimit64 <= uint64(^uint32(0)) {
				return invalid()
			}
			codeLimit = codeLimit64
		} else if codeLimit64 != 0 {
			return invalid()
		}
	}
	pageSize := uint64(1) << pageSizeExponent
	expectedCodeSlots := codeLimit / pageSize
	if codeLimit%pageSize != 0 {
		expectedCodeSlots++
	}
	if expectedCodeSlots != nCodeSlots {
		return invalid()
	}

	fullCDHash := sha256.Sum256(codeDirectory)
	if subtle.ConstantTimeCompare(
		fullCDHash[:transportCodeDirectoryCDHashSize], expectedCDHash,
	) != 1 {
		return transportParsedCodeDirectory{}, errors.New("transport library constraint CodeDirectory CDHash does not match Security.framework")
	}
	return transportParsedCodeDirectory{
		hashOffset:    hashOffset,
		nSpecialSlots: nSpecialSlots,
		hashSize:      hashSize,
	}, nil
}

func transportCodeDirectoryHeaderSize(version uint32) (uint64, bool) {
	switch version {
	case transportCodeDirectoryVersionBase:
		return transportCodeDirectoryBaseSize, true
	case transportCodeDirectoryVersionScatter:
		return 48, true
	case transportCodeDirectoryVersionTeam:
		return 52, true
	case transportCodeDirectoryVersionLimit64:
		return 64, true
	case transportCodeDirectoryVersionExecSeg:
		return 88, true
	case transportCodeDirectoryVersionRuntime:
		return 96, true
	default:
		return 0, false
	}
}

func transportCodeDirectoryStringTerminates(blob []byte, offset, limit uint64) bool {
	if offset >= limit || limit > uint64(len(blob)) {
		return false
	}
	for index := offset; index < limit; index++ {
		if blob[index] == 0 {
			return true
		}
	}
	return false
}

func verifyTransportLibraryConstraintSeal(
	codeDirectory []byte,
	parsed transportParsedCodeDirectory,
	constraint []byte,
) error {
	if parsed.nSpecialSlots < transportLibraryConstraintSpecialSlot ||
		parsed.hashSize != transportCodeDirectorySHA256Size {
		return errors.New("transport library constraint is not sealed by CodeDirectory slot -11")
	}
	sealOffset := parsed.hashOffset -
		transportLibraryConstraintSpecialSlot*parsed.hashSize
	if !transportConstraintRangeWithin(
		sealOffset, parsed.hashSize, uint64(len(codeDirectory)),
	) {
		return errors.New("transport library constraint CodeDirectory seal is out of range")
	}
	digest := sha256.Sum256(constraint)
	if subtle.ConstantTimeCompare(
		codeDirectory[sealOffset:sealOffset+parsed.hashSize], digest[:],
	) != 1 {
		return errors.New("transport library constraint is not sealed by CodeDirectory slot -11")
	}
	return nil
}

func transportConstraintRangesOverlap(
	firstOffset, firstSize, secondOffset, secondSize uint64,
) bool {
	return firstOffset < secondOffset+secondSize && secondOffset < firstOffset+firstSize
}

func transportConstraintRangeWithin(offset, size, limit uint64) bool {
	return offset <= limit && size <= limit-offset
}

func readTransportConstraintAt(file *os.File, offset uint64, destination []byte) error {
	read, err := file.ReadAt(destination, int64(offset))
	if err != nil {
		return err
	}
	if read != len(destination) {
		return io.ErrUnexpectedEOF
	}
	return nil
}
