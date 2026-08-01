declare module "ssh2/lib/protocol/keyParser.js" {
  type ParsedKey = import("ssh2").ParsedKey;

  const keyParser: {
    parseKey(
      data: Buffer | string | ParsedKey,
      passphrase?: Buffer | string,
    ): ParsedKey | ParsedKey[] | Error;
  };
  export default keyParser;
}
