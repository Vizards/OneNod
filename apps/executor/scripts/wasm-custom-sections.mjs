const WASM_HEADER = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
const FATAL_DECODER = new TextDecoder("utf-8", { fatal: true });

export function removeCustomSection(inputBytes, targetName) {
  const input = asWasmBuffer(inputBytes);
  if (typeof targetName !== "string" || targetName.length === 0) {
    throw new Error("custom section name must be non-empty");
  }

  const chunks = [input.subarray(0, WASM_HEADER.byteLength)];
  let offset = WASM_HEADER.byteLength;
  let removedCount = 0;

  while (offset < input.byteLength) {
    const sectionStart = offset;
    const sectionId = input[offset];
    offset += 1;
    const payloadLength = readU32Leb128(input, offset);
    offset = payloadLength.nextOffset;
    const payloadStart = offset;
    const sectionEnd = payloadStart + payloadLength.value;
    if (sectionEnd > input.byteLength) {
      throw new Error("truncated WebAssembly section");
    }

    let shouldRemove = false;
    if (sectionId === 0) {
      const nameLength = readU32Leb128(input, payloadStart);
      const nameStart = nameLength.nextOffset;
      const nameEnd = nameStart + nameLength.value;
      if (nameEnd > sectionEnd) {
        throw new Error("truncated WebAssembly custom section name");
      }
      const name = FATAL_DECODER.decode(input.subarray(nameStart, nameEnd));
      shouldRemove = name === targetName;
    }

    if (shouldRemove) {
      removedCount += 1;
    } else {
      chunks.push(input.subarray(sectionStart, sectionEnd));
    }
    offset = sectionEnd;
  }

  return { bytes: Buffer.concat(chunks), removedCount };
}

export function removeExportsByPrefix(inputBytes, targetPrefix) {
  const input = asWasmBuffer(inputBytes);
  if (typeof targetPrefix !== "string" || targetPrefix.length === 0) {
    throw new Error("export prefix must be non-empty");
  }

  const chunks = [input.subarray(0, WASM_HEADER.byteLength)];
  let offset = WASM_HEADER.byteLength;
  let exportSectionCount = 0;
  let removedCount = 0;

  while (offset < input.byteLength) {
    const sectionStart = offset;
    const sectionId = input[offset];
    offset += 1;
    const payloadLength = readU32Leb128(input, offset);
    offset = payloadLength.nextOffset;
    const payloadStart = offset;
    const sectionEnd = payloadStart + payloadLength.value;
    if (sectionEnd > input.byteLength) {
      throw new Error("truncated WebAssembly section");
    }

    if (sectionId !== 7) {
      chunks.push(input.subarray(sectionStart, sectionEnd));
      offset = sectionEnd;
      continue;
    }

    exportSectionCount += 1;
    const exportCount = readU32Leb128(input, payloadStart);
    offset = exportCount.nextOffset;
    const keptEntries = [];
    for (let index = 0; index < exportCount.value; index += 1) {
      const entryStart = offset;
      const nameLength = readU32Leb128(input, offset);
      offset = nameLength.nextOffset;
      const nameEnd = offset + nameLength.value;
      if (nameEnd > sectionEnd) {
        throw new Error("truncated WebAssembly export name");
      }
      const name = FATAL_DECODER.decode(input.subarray(offset, nameEnd));
      offset = nameEnd;
      if (offset >= sectionEnd) {
        throw new Error("truncated WebAssembly export kind");
      }
      const kind = input[offset];
      offset += 1;
      if (kind > 4) {
        throw new Error("unsupported WebAssembly export kind");
      }
      const itemIndex = readU32Leb128(input, offset);
      offset = itemIndex.nextOffset;

      if (name.startsWith(targetPrefix)) {
        removedCount += 1;
      } else {
        keptEntries.push(input.subarray(entryStart, offset));
      }
    }
    if (offset !== sectionEnd) {
      throw new Error("unexpected trailing bytes in WebAssembly export section");
    }

    const payload = Buffer.concat([
      encodeU32Leb128(keptEntries.length),
      ...keptEntries,
    ]);
    chunks.push(Buffer.from([sectionId]), encodeU32Leb128(payload.length), payload);
  }

  if (exportSectionCount !== 1) {
    throw new Error("expected exactly one WebAssembly export section");
  }
  return { bytes: Buffer.concat(chunks), removedCount };
}

function asWasmBuffer(inputBytes) {
  const input = Buffer.from(
    inputBytes.buffer,
    inputBytes.byteOffset,
    inputBytes.byteLength,
  );
  if (
    input.byteLength < WASM_HEADER.byteLength ||
    !input.subarray(0, WASM_HEADER.byteLength).equals(WASM_HEADER)
  ) {
    throw new Error("invalid WebAssembly header");
  }
  return input;
}

function readU32Leb128(bytes, startOffset) {
  let offset = startOffset;
  let value = 0;
  let shift = 0;
  for (let index = 0; index < 5; index += 1) {
    if (offset >= bytes.byteLength) {
      throw new Error("truncated WebAssembly LEB128 value");
    }
    const byte = bytes[offset];
    offset += 1;
    value += (byte & 0x7f) * 2 ** shift;
    if ((byte & 0x80) === 0) {
      if (!Number.isSafeInteger(value) || value > 0xffff_ffff) {
        throw new Error("WebAssembly LEB128 value exceeds uint32");
      }
      return { nextOffset: offset, value };
    }
    shift += 7;
  }
  throw new Error("WebAssembly LEB128 value exceeds uint32");
}

function encodeU32Leb128(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error("WebAssembly LEB128 input exceeds uint32");
  }
  const encoded = [];
  let remaining = value;
  do {
    let byte = remaining % 128;
    remaining = Math.floor(remaining / 128);
    if (remaining !== 0) byte |= 0x80;
    encoded.push(byte);
  } while (remaining !== 0);
  return Buffer.from(encoded);
}
