export function formatCountdown(
  value: string,
  now: number,
  label?: "Ends" | "Expires",
): string {
  const remainingMilliseconds = Date.parse(value) - now;
  if (!Number.isFinite(remainingMilliseconds) || remainingMilliseconds <= 0) {
    return "Expired";
  }
  const remainingSeconds = Math.ceil(remainingMilliseconds / 1_000);
  const hours = Math.floor(remainingSeconds / 3_600);
  const minutes = Math.floor((remainingSeconds % 3_600) / 60);
  const seconds = remainingSeconds % 60;
  const body = hours > 0
    ? `${padTime(hours)}:${padTime(minutes)}:${padTime(seconds)}`
    : `${padTime(minutes)}:${padTime(seconds)}`;
  return label ? `${label} in ${body}` : body;
}

export function shortIdentifier(value: string): string {
  if (value.length <= 18) return value;
  return `${value.slice(0, 8)}…${value.slice(-6)}`;
}

function padTime(value: number): string {
  return String(value).padStart(2, "0");
}
