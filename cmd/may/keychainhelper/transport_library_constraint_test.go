package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

type transportConstraintTestSlot struct {
	typeValue uint32
	blob      []byte
}

type transportConstraintTestFixture struct {
	content             []byte
	expectedCDHash      []byte
	signatureOffset     int
	codeDirectoryOffset int
	constraintOffset    int
}

func transportConstraintTestBlob(magic uint32, payload []byte) []byte {
	blob := make([]byte, transportGenericBlobHeader+len(payload))
	binary.BigEndian.PutUint32(blob[0:4], magic)
	binary.BigEndian.PutUint32(blob[4:8], uint32(len(blob)))
	copy(blob[8:], payload)
	return blob
}

func transportConstraintTestCodeDirectory(constraint []byte, specialSlots uint32) []byte {
	identifier := []byte("com.github.vizards.onenod.may\x00")
	specialHashStart := transportCodeDirectoryBaseSize + len(identifier)
	hashOffset := specialHashStart + int(specialSlots)*transportCodeDirectorySHA256Size
	codeDirectory := make([]byte, hashOffset+transportCodeDirectorySHA256Size)
	binary.BigEndian.PutUint32(codeDirectory[0:4], transportCodeDirectoryMagic)
	binary.BigEndian.PutUint32(codeDirectory[4:8], uint32(len(codeDirectory)))
	binary.BigEndian.PutUint32(codeDirectory[8:12], transportCodeDirectoryVersionBase)
	binary.BigEndian.PutUint32(codeDirectory[16:20], uint32(hashOffset))
	binary.BigEndian.PutUint32(codeDirectory[20:24], transportCodeDirectoryBaseSize)
	binary.BigEndian.PutUint32(codeDirectory[24:28], specialSlots)
	binary.BigEndian.PutUint32(codeDirectory[28:32], 1)
	binary.BigEndian.PutUint32(
		codeDirectory[32:36], transportMachO64HeaderSize+transportLinkeditCommandSize,
	)
	codeDirectory[36] = transportCodeDirectorySHA256Size
	codeDirectory[37] = transportCodeDirectorySHA256
	codeDirectory[39] = 12
	copy(codeDirectory[transportCodeDirectoryBaseSize:], identifier)
	if specialSlots >= transportLibraryConstraintSpecialSlot && constraint != nil {
		digest := sha256.Sum256(constraint)
		sealOffset := hashOffset -
			transportLibraryConstraintSpecialSlot*transportCodeDirectorySHA256Size
		copy(codeDirectory[sealOffset:sealOffset+transportCodeDirectorySHA256Size], digest[:])
	}
	return codeDirectory
}

func transportConstraintTestSuperBlob(slots ...transportConstraintTestSlot) []byte {
	indexEnd := transportSuperBlobHeader + len(slots)*transportSuperBlobIndex
	totalSize := indexEnd
	for _, slot := range slots {
		totalSize += len(slot.blob)
	}
	superBlob := make([]byte, totalSize)
	binary.BigEndian.PutUint32(superBlob[0:4], transportSuperBlobMagic)
	binary.BigEndian.PutUint32(superBlob[4:8], uint32(totalSize))
	binary.BigEndian.PutUint32(superBlob[8:12], uint32(len(slots)))
	blobOffset := indexEnd
	for index, slot := range slots {
		indexOffset := transportSuperBlobHeader + index*transportSuperBlobIndex
		binary.BigEndian.PutUint32(superBlob[indexOffset:indexOffset+4], slot.typeValue)
		binary.BigEndian.PutUint32(superBlob[indexOffset+4:indexOffset+8], uint32(blobOffset))
		copy(superBlob[blobOffset:], slot.blob)
		blobOffset += len(slot.blob)
	}
	return superBlob
}

func transportConstraintTestMachO(commands []uint32, signature []byte, padding int) []byte {
	commandBytes := len(commands) * transportLinkeditCommandSize
	signatureOffset := transportMachO64HeaderSize + commandBytes
	fileBytes := make([]byte, signatureOffset+len(signature)+padding)
	binary.LittleEndian.PutUint32(fileBytes[0:4], transportMachO64Magic)
	binary.LittleEndian.PutUint32(fileBytes[4:8], transportCPUTypeARM64)
	binary.LittleEndian.PutUint32(fileBytes[12:16], 2) // MH_EXECUTE
	binary.LittleEndian.PutUint32(fileBytes[16:20], uint32(len(commands)))
	binary.LittleEndian.PutUint32(fileBytes[20:24], uint32(commandBytes))
	for index, command := range commands {
		offset := transportMachO64HeaderSize + index*transportLinkeditCommandSize
		binary.LittleEndian.PutUint32(fileBytes[offset:offset+4], command)
		binary.LittleEndian.PutUint32(fileBytes[offset+4:offset+8], transportLinkeditCommandSize)
		if command == transportLCCodeSignature {
			binary.LittleEndian.PutUint32(fileBytes[offset+8:offset+12], uint32(signatureOffset))
			binary.LittleEndian.PutUint32(fileBytes[offset+12:offset+16], uint32(len(signature)+padding))
		}
	}
	copy(fileBytes[signatureOffset:], signature)
	return fileBytes
}

func newTransportConstraintTestFixture(constraint []byte, specialSlots uint32) transportConstraintTestFixture {
	codeDirectory := transportConstraintTestCodeDirectory(constraint, specialSlots)
	slots := []transportConstraintTestSlot{{
		typeValue: transportPrimaryCodeDirectorySlot,
		blob:      codeDirectory,
	}}
	constraintOffset := 0
	if constraint != nil {
		slots = append(slots, transportConstraintTestSlot{
			typeValue: transportConstraintSlot,
			blob:      constraint,
		})
	}
	superBlob := transportConstraintTestSuperBlob(slots...)
	signatureOffset := transportMachO64HeaderSize + transportLinkeditCommandSize
	codeDirectoryOffset := transportSuperBlobHeader + len(slots)*transportSuperBlobIndex
	if constraint != nil {
		constraintOffset = codeDirectoryOffset + len(codeDirectory)
	}
	fullCDHash := sha256.Sum256(codeDirectory)
	return transportConstraintTestFixture{
		content: transportConstraintTestMachO(
			[]uint32{transportLCCodeSignature}, superBlob, 64,
		),
		expectedCDHash:      append([]byte(nil), fullCDHash[:transportCodeDirectoryCDHashSize]...),
		signatureOffset:     signatureOffset,
		codeDirectoryOffset: codeDirectoryOffset,
		constraintOffset:    constraintOffset,
	}
}

func (fixture transportConstraintTestFixture) codeDirectory() []byte {
	start := fixture.signatureOffset + fixture.codeDirectoryOffset
	length := int(binary.BigEndian.Uint32(fixture.content[start+4 : start+8]))
	return fixture.content[start : start+length]
}

func (fixture *transportConstraintTestFixture) refreshExpectedCDHash() {
	digest := sha256.Sum256(fixture.codeDirectory())
	fixture.expectedCDHash = append(
		fixture.expectedCDHash[:0], digest[:transportCodeDirectoryCDHashSize]...,
	)
}

func transportConstraintTestFile(t *testing.T, content []byte) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "transport")
	if err := os.WriteFile(path, content, 0o500); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func TestTransportLibraryConstraintBlobReturnsExactSealedBlobWithoutChangingPosition(t *testing.T) {
	expected := transportConstraintTestBlob(
		transportConstraintMagic,
		[]byte("team-identifier=2BUA8C4S2C"),
	)
	fixture := newTransportConstraintTestFixture(
		expected, transportLibraryConstraintSpecialSlot,
	)
	file := transportConstraintTestFile(t, fixture.content)
	if _, err := file.Seek(7, 0); err != nil {
		t.Fatal(err)
	}

	actual, err := transportLibraryConstraintBlob(file, fixture.expectedCDHash)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("constraint mismatch: got %x want %x", actual, expected)
	}
	position, err := file.Seek(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if position != 7 {
		t.Fatalf("file position changed: got %d want 7", position)
	}
}

func TestTransportLibraryConstraintBlobReturnsNilForLegacySignatureWithoutSlot11(t *testing.T) {
	fixture := newTransportConstraintTestFixture(nil, 2)
	binary.LittleEndian.PutUint32(fixture.content[4:8], transportCPUTypeAMD64)
	file := transportConstraintTestFile(t, fixture.content)

	blob, err := transportLibraryConstraintBlob(file, fixture.expectedCDHash)
	if err != nil {
		t.Fatal(err)
	}
	if blob != nil {
		t.Fatalf("unexpected constraint: %x", blob)
	}
}

func TestTransportLibraryConstraintBlobRequiresExactCDHashAndSlot11Seal(t *testing.T) {
	constraint := transportConstraintTestBlob(transportConstraintMagic, []byte("constraint"))

	tests := []struct {
		name   string
		mutate func(*transportConstraintTestFixture)
		build  func() transportConstraintTestFixture
	}{
		{
			name: "zero slot -11 seal",
			mutate: func(fixture *transportConstraintTestFixture) {
				codeDirectory := fixture.codeDirectory()
				hashOffset := int(binary.BigEndian.Uint32(codeDirectory[16:20]))
				sealOffset := hashOffset -
					transportLibraryConstraintSpecialSlot*transportCodeDirectorySHA256Size
				clear(codeDirectory[sealOffset : sealOffset+transportCodeDirectorySHA256Size])
				fixture.refreshExpectedCDHash()
			},
		},
		{
			name: "wrong slot -11 seal",
			mutate: func(fixture *transportConstraintTestFixture) {
				codeDirectory := fixture.codeDirectory()
				hashOffset := int(binary.BigEndian.Uint32(codeDirectory[16:20]))
				sealOffset := hashOffset -
					transportLibraryConstraintSpecialSlot*transportCodeDirectorySHA256Size
				for index := 0; index < transportCodeDirectorySHA256Size; index++ {
					codeDirectory[sealOffset+index] = 0xa5
				}
				fixture.refreshExpectedCDHash()
			},
		},
		{
			name: "constraint tamper",
			mutate: func(fixture *transportConstraintTestFixture) {
				absolute := fixture.signatureOffset + fixture.constraintOffset
				fixture.content[absolute+transportGenericBlobHeader] ^= 0x01
			},
		},
		{
			name: "CodeDirectory tamper",
			mutate: func(fixture *transportConstraintTestFixture) {
				fixture.codeDirectory()[15] ^= 0x01
			},
		},
		{
			name: "Security CDHash mismatch",
			mutate: func(fixture *transportConstraintTestFixture) {
				fixture.expectedCDHash[0] ^= 0x01
			},
		},
		{
			name: "fewer than eleven special slots",
			build: func() transportConstraintTestFixture {
				return newTransportConstraintTestFixture(constraint, 10)
			},
		},
		{
			name: "unsupported hash type",
			mutate: func(fixture *transportConstraintTestFixture) {
				fixture.codeDirectory()[37] = 1
				fixture.refreshExpectedCDHash()
			},
		},
		{
			name: "unsupported hash size",
			mutate: func(fixture *transportConstraintTestFixture) {
				fixture.codeDirectory()[36] = 20
				fixture.refreshExpectedCDHash()
			},
		},
		{
			name: "zero page size",
			mutate: func(fixture *transportConstraintTestFixture) {
				fixture.codeDirectory()[39] = 0
				fixture.refreshExpectedCDHash()
			},
		},
		{
			name: "unsupported CodeDirectory version",
			mutate: func(fixture *transportConstraintTestFixture) {
				binary.BigEndian.PutUint32(fixture.codeDirectory()[8:12], 0x20501)
				fixture.refreshExpectedCDHash()
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTransportConstraintTestFixture(
				constraint, transportLibraryConstraintSpecialSlot,
			)
			if test.build != nil {
				fixture = test.build()
			}
			if test.mutate != nil {
				test.mutate(&fixture)
			}
			file := transportConstraintTestFile(t, fixture.content)
			if blob, err := transportLibraryConstraintBlob(
				file, fixture.expectedCDHash,
			); err == nil {
				t.Fatalf("accepted unsealed or mismatched constraint %x", blob)
			}
		})
	}
}

func TestTransportLibraryConstraintBlobRejectsPrimaryCodeDirectoryAmbiguity(t *testing.T) {
	constraint := transportConstraintTestBlob(transportConstraintMagic, []byte("constraint"))
	codeDirectory := transportConstraintTestCodeDirectory(
		constraint, transportLibraryConstraintSpecialSlot,
	)
	digest := sha256.Sum256(codeDirectory)
	expectedCDHash := digest[:transportCodeDirectoryCDHashSize]

	for _, test := range []struct {
		name  string
		slots []transportConstraintTestSlot
	}{
		{
			name: "duplicate primary",
			slots: []transportConstraintTestSlot{
				{typeValue: transportPrimaryCodeDirectorySlot, blob: codeDirectory},
				{typeValue: transportPrimaryCodeDirectorySlot, blob: codeDirectory},
				{typeValue: transportConstraintSlot, blob: constraint},
			},
		},
		{
			name: "alternate CodeDirectory",
			slots: []transportConstraintTestSlot{
				{typeValue: transportPrimaryCodeDirectorySlot, blob: codeDirectory},
				{typeValue: transportAlternateCodeDirectoryFirst, blob: codeDirectory},
				{typeValue: transportConstraintSlot, blob: constraint},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			file := transportConstraintTestFile(t, transportConstraintTestMachO(
				[]uint32{transportLCCodeSignature},
				transportConstraintTestSuperBlob(test.slots...), 0,
			))
			if blob, err := transportLibraryConstraintBlob(file, expectedCDHash); err == nil {
				t.Fatalf("accepted ambiguous CodeDirectory with blob %x", blob)
			}
		})
	}
}

func TestTransportLibraryConstraintBlobRejectsEveryTruncation(t *testing.T) {
	constraint := transportConstraintTestBlob(transportConstraintMagic, []byte("constraint"))
	fixture := newTransportConstraintTestFixture(
		constraint, transportLibraryConstraintSpecialSlot,
	)
	for length := 0; length < len(fixture.content); length++ {
		file := transportConstraintTestFile(t, fixture.content[:length])
		if blob, err := transportLibraryConstraintBlob(
			file, fixture.expectedCDHash,
		); err == nil {
			t.Fatalf("accepted input truncated to %d bytes with blob %x", length, blob)
		}
	}
}

func TestTransportLibraryConstraintBlobRejectsMalformedMachOAndCodeSignature(t *testing.T) {
	constraint := transportConstraintTestBlob(transportConstraintMagic, []byte("constraint"))
	valid := func() transportConstraintTestFixture {
		return newTransportConstraintTestFixture(
			constraint, transportLibraryConstraintSpecialSlot,
		)
	}

	tests := []struct {
		name   string
		mutate func(*transportConstraintTestFixture)
	}{
		{
			name: "fat binary",
			mutate: func(fixture *transportConstraintTestFixture) {
				binary.BigEndian.PutUint32(fixture.content[0:4], 0xcafebabe)
			},
		},
		{
			name: "unsupported thin architecture",
			mutate: func(fixture *transportConstraintTestFixture) {
				binary.LittleEndian.PutUint32(fixture.content[4:8], 7)
			},
		},
		{
			name: "zero-sized load command",
			mutate: func(fixture *transportConstraintTestFixture) {
				binary.LittleEndian.PutUint32(fixture.content[36:40], 0)
			},
		},
		{
			name: "load commands exceed file",
			mutate: func(fixture *transportConstraintTestFixture) {
				binary.LittleEndian.PutUint32(fixture.content[20:24], uint32(len(fixture.content)))
			},
		},
		{
			name: "code signature offset exceeds file",
			mutate: func(fixture *transportConstraintTestFixture) {
				binary.LittleEndian.PutUint32(fixture.content[40:44], uint32(len(fixture.content)))
			},
		},
		{
			name: "code signature range is truncated",
			mutate: func(fixture *transportConstraintTestFixture) {
				binary.LittleEndian.PutUint32(fixture.content[44:48], uint32(len(fixture.content)))
			},
		},
		{
			name: "bad SuperBlob magic",
			mutate: func(fixture *transportConstraintTestFixture) {
				binary.BigEndian.PutUint32(
					fixture.content[fixture.signatureOffset:fixture.signatureOffset+4], 0xfade0c01,
				)
			},
		},
		{
			name: "SuperBlob length exceeds command range",
			mutate: func(fixture *transportConstraintTestFixture) {
				signature := fixture.content[fixture.signatureOffset:]
				binary.BigEndian.PutUint32(signature[4:8], uint32(len(signature)+1))
			},
		},
		{
			name: "index table exceeds SuperBlob",
			mutate: func(fixture *transportConstraintTestFixture) {
				binary.BigEndian.PutUint32(
					fixture.content[fixture.signatureOffset+8:fixture.signatureOffset+12], 100,
				)
			},
		},
		{
			name: "primary slot overlaps index table",
			mutate: func(fixture *transportConstraintTestFixture) {
				binary.BigEndian.PutUint32(
					fixture.content[fixture.signatureOffset+16:fixture.signatureOffset+20], 12,
				)
			},
		},
		{
			name: "primary slot exceeds SuperBlob",
			mutate: func(fixture *transportConstraintTestFixture) {
				signature := fixture.content[fixture.signatureOffset:]
				superBlobSize := binary.BigEndian.Uint32(signature[4:8])
				binary.BigEndian.PutUint32(signature[16:20], superBlobSize)
			},
		},
		{
			name: "wrong library constraint blob magic",
			mutate: func(fixture *transportConstraintTestFixture) {
				absolute := fixture.signatureOffset + fixture.constraintOffset
				binary.BigEndian.PutUint32(fixture.content[absolute:absolute+4], transportCodeDirectoryMagic)
			},
		},
		{
			name: "library constraint declared length is too small",
			mutate: func(fixture *transportConstraintTestFixture) {
				absolute := fixture.signatureOffset + fixture.constraintOffset
				binary.BigEndian.PutUint32(fixture.content[absolute+4:absolute+8], 7)
			},
		},
		{
			name: "library constraint declared length exceeds SuperBlob",
			mutate: func(fixture *transportConstraintTestFixture) {
				absolute := fixture.signatureOffset + fixture.constraintOffset
				binary.BigEndian.PutUint32(
					fixture.content[absolute+4:absolute+8], uint32(len(fixture.content)),
				)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := valid()
			test.mutate(&fixture)
			file := transportConstraintTestFile(t, fixture.content)
			if blob, err := transportLibraryConstraintBlob(
				file, fixture.expectedCDHash,
			); err == nil {
				t.Fatalf("accepted malformed input with blob %x", blob)
			}
		})
	}
}
