import { formatCountdown, formatDateTime } from "../utils/presentation";

export function LiveCountdown({
  expiresAt,
  label,
  now,
}: {
  expiresAt: string;
  label?: "Ends" | "Expires";
  now: number;
}) {
  return (
    <time dateTime={expiresAt} title={formatDateTime(expiresAt)}>
      {formatCountdown(expiresAt, now, label)}
    </time>
  );
}
