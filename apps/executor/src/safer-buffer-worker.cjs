"use strict";

// Adapted from safer-buffer 2.1.2 by Nikita Skovoroda.
// MIT licensed; see ../third_party/licenses/safer-buffer-2.1.2.txt.
// `asn1`, used by the pinned SSH parser, needs the safer-buffer API surface.
// Its upstream compatibility shim probes `process.binding("buffer")`, which is
// unnecessary in Workers. Export the same safe constructors without exposing
// that process-internal capability in the deployed artifact.
const buffer = require("node:buffer");

const safer = {};
for (const key of Object.keys(buffer)) {
  if (key !== "SlowBuffer" && key !== "Buffer") safer[key] = buffer[key];
}

const Buffer = buffer.Buffer;
const SaferBuffer = {};
for (const key of Object.keys(Buffer)) {
  if (key !== "allocUnsafe" && key !== "allocUnsafeSlow") {
    SaferBuffer[key] = Buffer[key];
  }
}
SaferBuffer.prototype = Buffer.prototype;
safer.Buffer = SaferBuffer;

module.exports = safer;
