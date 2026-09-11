package main

import (
	"regexp"
	"strings"
)

type transcriptContentPart struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

var imageAttachmentOpening = regexp.MustCompile(`^<image name=\[Image #[1-9][0-9]*\](?: path="[^"\r\n]+")?>$`)

// promptWithoutImageWrappers projects the text represented by UserPromptSubmit.
// Codex stores attachment wrappers as separate text/image/text content items in
// the transcript, although they are absent from the submitted prompt. Only that
// complete structure may be removed; all other text, including empty items and
// text after an image, retains its exact bytes and order. Callers must still
// compare the result with the protected Core prompt or its digest.
// Keep this small adapter identical in the standalone Core/Gatekeeper modules;
// both run the shared transcript fixtures without adding a runtime dependency.
func promptWithoutImageWrappers(content []transcriptContentPart) (string, bool) {
	var pieces []string
	unwrapped := false
	for index := 0; index < len(content); index++ {
		part := content[index]
		if index+2 < len(content) && part.Type == "input_text" &&
			imageAttachmentOpening.MatchString(part.Text) &&
			content[index+1].Type == "input_image" &&
			content[index+2].Type == "input_text" && content[index+2].Text == "</image>" {
			unwrapped = true
			index += 2
			continue
		}
		if part.Type == "input_text" || part.Type == "text" || part.Type == "output_text" {
			pieces = append(pieces, part.Text)
		}
	}
	return strings.Join(pieces, "\n"), unwrapped
}
