import type { CallContext, ExtismPluginOptions } from "@extism/extism";

const MAX_RANDOM_BYTES_PER_CALL = 1024 * 1024;

export const HOST_FUNCTION_NAMES = [
  "op-extism-core.random_fill_imported",
  "op-now.unix_time_milliseconds_imported",
  "op-time.utc_offset_seconds",
  "zxcvbn.unix_time_milliseconds_imported",
] as const;

export function createOnePasswordHostFunctions(): NonNullable<
  ExtismPluginOptions["functions"]
> {
  const unixTimeMilliseconds = (): bigint => BigInt(Date.now());

  return {
    "op-extism-core": {
      random_fill_imported(context: CallContext, requestedLength: number): bigint {
        const length = requestedLength >>> 0;
        if (length > MAX_RANDOM_BYTES_PER_CALL) {
          throw new RangeError("core requested too many random bytes");
        }
        const bytes = new Uint8Array(length);
        for (let offset = 0; offset < bytes.length; offset += 65_536) {
          crypto.getRandomValues(bytes.subarray(offset, Math.min(offset + 65_536, bytes.length)));
        }
        return context.store(bytes);
      },
    },
    "op-now": {
      unix_time_milliseconds_imported: unixTimeMilliseconds,
    },
    "op-time": {
      utc_offset_seconds: (): bigint => 0n,
    },
    zxcvbn: {
      unix_time_milliseconds_imported: unixTimeMilliseconds,
    },
  };
}
