package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClientTransportLogConcurrentAppendKeepsWholeRecords(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	if err := os.Mkdir(filepath.Join(root, userAgentDirectoryName), 0o700); err != nil {
		t.Fatal(err)
	}
	var logs []*transportLog
	var files []*os.File
	for _, trace := range []string{strings.Repeat("a", 32), strings.Repeat("b", 32)} {
		file, err := openClientTransportLog()
		if err != nil {
			t.Fatal(err)
		}
		log := newTransportLog(file)
		files = append(files, file)
		logs = append(logs, log)
		observation := newTransportObservation(log, "ssh-client", trace)
		for range 20 {
			observation.begin("binding-read", 2*time.Second).finish(nil)
		}
	}
	for index, log := range logs {
		log.close()
		select {
		case <-log.done:
		case <-time.After(time.Second):
			t.Fatal("append log did not drain")
		}
		files[index].Close()
	}
	data, err := os.ReadFile(filepath.Join(root, userAgentDirectoryName, "logs", "beholder-handshake.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var event transportLogEvent
		err := decoder.Decode(&event)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal("concurrent appends interleaved a JSON record")
		}
		counts[event.TraceID]++
	}
	if counts[strings.Repeat("a", 32)] != 40 || counts[strings.Repeat("b", 32)] != 40 {
		t.Fatal("concurrent writer lost or reassigned events")
	}
}

func TestClientTransportLogIsPrivateAndRejectsRedirectedPaths(t *testing.T) {
	for _, variant := range []string{"private", "public-file", "file-symlink", "directory-symlink", "hard-link"} {
		t.Run(variant, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("HOME", root)
			directory := filepath.Join(root, userAgentDirectoryName, "logs")
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "beholder-handshake.jsonl")
			target := filepath.Join(root, "unrelated")
			if err := os.WriteFile(target, []byte("must remain unchanged"), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch variant {
			case "public-file":
				err = os.WriteFile(path, nil, 0644)
			case "file-symlink":
				err = os.Symlink(target, path)
			case "directory-symlink":
				if err = os.Remove(directory); err == nil {
					err = os.Symlink(root, directory)
				}
			case "hard-link":
				err = os.Link(target, path)
			}
			if err != nil {
				t.Fatal(err)
			}
			file, err := openClientTransportLog()
			if variant == "private" {
				if err != nil {
					t.Fatal(err)
				}
				info, _ := file.Stat()
				file.Close()
				if info.Mode().Perm() != 0600 {
					t.Fatal("log is not private")
				}
			} else if err == nil {
				file.Close()
				t.Fatal("unsafe log path was accepted")
			}
			contents, _ := os.ReadFile(target)
			if string(contents) != "must remain unchanged" {
				t.Fatal("logging modified an unrelated file")
			}
		})
	}
}
