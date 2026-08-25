import { STATUS_LABEL, type SecurityStatus } from "../types";
import { STATUS_COLOR } from "./Shield";

/** שבב מצב. הצבע נושא את המידע, הטקסט מאשר אותו. */
export function StatusChip({ status }: { status: SecurityStatus | null }) {
  const value: SecurityStatus = status ?? "unknown";
  const color = STATUS_COLOR[value];

  return (
    <span
      className="chip"
      style={{ borderColor: `${color}66`, background: `${color}1a`, color }}
    >
      <span className="dot" style={{ background: color }} />
      {STATUS_LABEL[value]}
    </span>
  );
}
