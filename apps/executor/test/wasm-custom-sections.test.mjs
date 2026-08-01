import assert from "node:assert/strict";
import test from "node:test";

import {
  removeCustomSection,
  removeExportsByPrefix,
} from "../scripts/wasm-custom-sections.mjs";

const WASM_HEADER = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

test("custom-section removal preserves the executable module", () => {
  const input = Buffer.concat([
    WASM_HEADER,
    customSection("keep", Buffer.from([1, 2, 3])),
    customSection("drop", Buffer.from([4, 5, 6])),
  ]);
  const before = new WebAssembly.Module(input);

  const result = removeCustomSection(input, "drop");
  const after = new WebAssembly.Module(result.bytes);

  assert.equal(result.removedCount, 1);
  assert.equal(WebAssembly.Module.customSections(after, "drop").length, 0);
  assert.equal(WebAssembly.Module.customSections(after, "keep").length, 1);
  assert.deepEqual(WebAssembly.Module.imports(after), WebAssembly.Module.imports(before));
  assert.deepEqual(WebAssembly.Module.exports(after), WebAssembly.Module.exports(before));
});

test("custom-section removal fails closed for malformed input", () => {
  assert.throws(
    () => removeCustomSection(Buffer.from([0x00, 0x61, 0x73]), "drop"),
    /invalid WebAssembly header/,
  );
  assert.throws(
    () =>
      removeCustomSection(
        Buffer.concat([WASM_HEADER, Buffer.from([0x00, 0x80])]),
        "drop",
      ),
    /truncated WebAssembly LEB128/,
  );
});

test("export pruning hides only the selected prefix", () => {
  const input = minimalModuleWithExports(["keep", "__describe_one", "__describe_two"]);
  const before = new WebAssembly.Module(input);

  const result = removeExportsByPrefix(input, "__describe_");
  const after = new WebAssembly.Module(result.bytes);

  assert.equal(result.removedCount, 2);
  assert.deepEqual(WebAssembly.Module.imports(after), WebAssembly.Module.imports(before));
  assert.deepEqual(WebAssembly.Module.exports(after), [
    { kind: "function", name: "keep" },
  ]);
});

function customSection(name, payload) {
  const encodedName = Buffer.from(name, "utf8");
  const content = Buffer.concat([encodeU32(encodedName.length), encodedName, payload]);
  return Buffer.concat([Buffer.from([0x00]), encodeU32(content.length), content]);
}

function encodeU32(value) {
  const bytes = [];
  let remaining = value;
  do {
    let byte = remaining & 0x7f;
    remaining >>>= 7;
    if (remaining !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (remaining !== 0);
  return Buffer.from(bytes);
}

function minimalModuleWithExports(names) {
  const typeSection = section(1, Buffer.from([0x01, 0x60, 0x00, 0x00]));
  const functionSection = section(3, Buffer.from([0x01, 0x00]));
  const exportEntries = names.map((name) => {
    const encoded = Buffer.from(name, "utf8");
    return Buffer.concat([
      encodeU32(encoded.length),
      encoded,
      Buffer.from([0x00, 0x00]),
    ]);
  });
  const exportSection = section(
    7,
    Buffer.concat([encodeU32(exportEntries.length), ...exportEntries]),
  );
  const codeSection = section(10, Buffer.from([0x01, 0x02, 0x00, 0x0b]));
  return Buffer.concat([
    WASM_HEADER,
    typeSection,
    functionSection,
    exportSection,
    codeSection,
  ]);
}

function section(id, payload) {
  return Buffer.concat([Buffer.from([id]), encodeU32(payload.length), payload]);
}
