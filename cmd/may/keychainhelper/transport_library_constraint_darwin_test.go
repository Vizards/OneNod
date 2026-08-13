//go:build darwin && cgo

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

type transportConstraintRealSignature struct {
	signatureOffset         int
	codeDirectoryOffset     int
	constraintOffset        int
	constraintIndexTypeByte int
}

func locateTransportConstraintRealSignature(
	t *testing.T,
	content []byte,
) transportConstraintRealSignature {
	t.Helper()
	if len(content) < transportMachO64HeaderSize ||
		binary.LittleEndian.Uint32(content[0:4]) != transportMachO64Magic {
		t.Fatal("codesign test output is not a thin 64-bit Mach-O")
	}
	commandCount := int(binary.LittleEndian.Uint32(content[16:20]))
	commandOffset := transportMachO64HeaderSize
	signatureOffset := 0
	for index := 0; index < commandCount; index++ {
		if commandOffset+transportLoadCommandSize > len(content) {
			t.Fatal("codesign test output has a truncated load command")
		}
		command := binary.LittleEndian.Uint32(content[commandOffset : commandOffset+4])
		commandSize := int(binary.LittleEndian.Uint32(content[commandOffset+4 : commandOffset+8]))
		if commandSize < transportLoadCommandSize || commandOffset+commandSize > len(content) {
			t.Fatal("codesign test output has an invalid load command")
		}
		if command == transportLCCodeSignature {
			if signatureOffset != 0 || commandSize != transportLinkeditCommandSize {
				t.Fatal("codesign test output has ambiguous code signature commands")
			}
			signatureOffset = int(binary.LittleEndian.Uint32(
				content[commandOffset+8 : commandOffset+12],
			))
		}
		commandOffset += commandSize
	}
	if signatureOffset <= 0 || signatureOffset+transportSuperBlobHeader > len(content) ||
		binary.BigEndian.Uint32(
			content[signatureOffset:signatureOffset+4],
		) != transportSuperBlobMagic {
		t.Fatal("codesign test output has no embedded SuperBlob")
	}
	indexCount := int(binary.BigEndian.Uint32(
		content[signatureOffset+8 : signatureOffset+12],
	))
	result := transportConstraintRealSignature{signatureOffset: signatureOffset}
	for index := 0; index < indexCount; index++ {
		indexOffset := signatureOffset + transportSuperBlobHeader +
			index*transportSuperBlobIndex
		if indexOffset+transportSuperBlobIndex > len(content) {
			t.Fatal("codesign test output has a truncated SuperBlob index")
		}
		slotType := binary.BigEndian.Uint32(content[indexOffset : indexOffset+4])
		blobOffset := int(binary.BigEndian.Uint32(content[indexOffset+4 : indexOffset+8]))
		switch slotType {
		case transportPrimaryCodeDirectorySlot:
			result.codeDirectoryOffset = blobOffset
		case transportConstraintSlot:
			result.constraintOffset = blobOffset
			result.constraintIndexTypeByte = indexOffset
		}
	}
	if result.codeDirectoryOffset == 0 || result.constraintOffset == 0 ||
		result.constraintIndexTypeByte == 0 {
		t.Fatal("codesign test output omitted the primary CodeDirectory or library constraint")
	}
	return result
}

func TestTransportLibraryConstraintBlobVerifiesRealCodesignSeal(t *testing.T) {
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "main.go")
	binaryPath := filepath.Join(directory, "may")
	constraintPath := filepath.Join(directory, "library-constraint.plist")
	if err := os.WriteFile(
		sourcePath, []byte("package main\nfunc main() {}\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(
		"go", "build", "-o", binaryPath, sourcePath,
	).CombinedOutput(); err != nil {
		t.Fatalf("build codesign constraint fixture: %v: %s", err, output)
	}
	if err := os.WriteFile(
		constraintPath, []byte(testOnePasswordLibraryConstraintPlist), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(
		"/usr/bin/codesign", "--force", "--sign", "-", "--options", "runtime",
		"--digest-algorithm=sha256", "--identifier", oneNodMaySigningIdentifier,
		"--library-constraint", constraintPath, binaryPath,
	).CombinedOutput(); err != nil {
		t.Fatalf("sign codesign constraint fixture: %v: %s", err, output)
	}
	content, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	located := locateTransportConstraintRealSignature(t, content)
	codeDirectoryStart := located.signatureOffset + located.codeDirectoryOffset
	codeDirectoryLength := int(binary.BigEndian.Uint32(
		content[codeDirectoryStart+4 : codeDirectoryStart+8],
	))
	codeDirectory := content[codeDirectoryStart : codeDirectoryStart+codeDirectoryLength]
	fullCDHash := sha256.Sum256(codeDirectory)
	expectedCDHash := append(
		[]byte(nil), fullCDHash[:transportCodeDirectoryCDHashSize]...,
	)
	file, err := os.Open(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	constraint, err := transportLibraryConstraintBlob(file, expectedCDHash)
	_ = file.Close()
	if err != nil || len(constraint) < transportGenericBlobHeader ||
		binary.BigEndian.Uint32(constraint[0:4]) != transportConstraintMagic {
		t.Fatalf("real codesign seal was rejected: constraint=%x error=%v", constraint, err)
	}

	tests := []struct {
		name   string
		mutate func([]byte, *[]byte)
	}{
		{
			name: "Security CDHash mismatch",
			mutate: func(_ []byte, expected *[]byte) {
				(*expected)[0] ^= 0x01
			},
		},
		{
			name: "CodeDirectory tamper",
			mutate: func(mutated []byte, _ *[]byte) {
				mutated[codeDirectoryStart+15] ^= 0x01
			},
		},
		{
			name: "zero slot -11 seal",
			mutate: func(mutated []byte, expected *[]byte) {
				mutatedCodeDirectory := mutated[codeDirectoryStart : codeDirectoryStart+codeDirectoryLength]
				hashOffset := int(binary.BigEndian.Uint32(mutatedCodeDirectory[16:20]))
				sealOffset := hashOffset -
					transportLibraryConstraintSpecialSlot*transportCodeDirectorySHA256Size
				clear(mutatedCodeDirectory[sealOffset : sealOffset+transportCodeDirectorySHA256Size])
				digest := sha256.Sum256(mutatedCodeDirectory)
				*expected = append(
					(*expected)[:0], digest[:transportCodeDirectoryCDHashSize]...,
				)
			},
		},
		{
			name: "constraint tamper",
			mutate: func(mutated []byte, _ *[]byte) {
				constraintStart := located.signatureOffset + located.constraintOffset
				constraintLength := int(binary.BigEndian.Uint32(
					mutated[constraintStart+4 : constraintStart+8],
				))
				mutated[constraintStart+constraintLength-1] ^= 0x01
			},
		},
		{
			name: "alternate CodeDirectory",
			mutate: func(mutated []byte, _ *[]byte) {
				indexStart := located.constraintIndexTypeByte
				binary.BigEndian.PutUint32(
					mutated[indexStart:indexStart+4], transportAlternateCodeDirectoryFirst,
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := append([]byte(nil), content...)
			mutatedExpectedCDHash := append([]byte(nil), expectedCDHash...)
			test.mutate(mutated, &mutatedExpectedCDHash)
			mutatedFile := transportConstraintTestFile(t, mutated)
			if blob, err := transportLibraryConstraintBlob(
				mutatedFile, mutatedExpectedCDHash,
			); err == nil {
				t.Fatalf("accepted mutated real signature with constraint %x", blob)
			}
		})
	}
}
