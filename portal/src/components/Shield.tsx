import type { SecurityStatus } from "../types";

/**
 * המגן של SafeMe.
 *
 * מסלול ה-SVG הוא תרגום מדויק של ShieldRenderer.BuildShieldPath ב-C#,
 * באותה מערכת קואורדינטות של 0..100. כך הצורה בפורטל זהה לזו שבאייקון
 * התוכנה, באייקון המגש ובתג הצף.
 */

const SHIELD =
  "M 8,15 A 10,10 0 0 1 18,5 L 82,5 A 10,10 0 0 1 92,15 " +
  "L 92,32 C 92,62 78,81 50,96 C 22,81 8,62 8,32 Z";

const CHECK = "M 31,52 L 43,64 L 69,36";

export const STATUS_COLOR: Record<SecurityStatus, string> = {
  safe: "#22a058",
  low_filter: "#d68e0c",
  unfiltered: "#ce382e",
  blocked: "#6b7480",
  unknown: "#8c96a3",
};

export function Shield({
  status = "unknown",
  size = 22,
  color,
}: {
  status?: SecurityStatus;
  size?: number;
  color?: string;
}) {
  const fill = color ?? STATUS_COLOR[status];

  return (
    <svg width={size} height={size} viewBox="0 0 100 100" aria-hidden="true">
      <path d={SHIELD} fill={fill} />
      <path d={SHIELD} fill="none" stroke="rgba(255,255,255,0.28)" strokeWidth="2" />
      {size >= 18 && (
        <path
          d={CHECK}
          fill="none"
          stroke="#fff"
          strokeWidth="9"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      )}
    </svg>
  );
}
