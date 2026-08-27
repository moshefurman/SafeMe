/**
 * מייצר וקטורי בדיקה לכלל ה-default-deny.
 *
 * הרשימות מוגדרות פעמיים — פעם ב-TypeScript ופעם ב-C# — כי כל צד
 * צריך אותן גם בלי השני. שתי הגדרות של אותו דבר נפרדות במוקדם או
 * במאוחר, וזה בדיוק מה שקרה כבר פעם אחת בתבנית שם הקובץ.
 *
 * הפתרון אינו לזכור לעדכן את שניהם, אלא לבדוק.
 */

import { readFileSync, writeFileSync } from "node:fs";

import { BASELINE_BLOCKED_PORTS, buildEgressRule, describeEgress } from "../src/policy/egress.ts";

const path = new URL("../../shared/test-vectors.json", import.meta.url);
const vectors = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;

vectors["egress"] = {
  baselineBlockedPorts: BASELINE_BLOCKED_PORTS,

  cases: [
    {
      name: "כבוי",
      options: { enabled: false },
      expectPosture: "Off",
    },
    {
      name: "סינון ברמת הספק",
      options: { enabled: true, resolvers: ["198.51.100.5/32"] },
      expectPosture: "Filtered",
    },
    {
      name: "שרתי ספק",
      options: {
        enabled: true,
        mode: "proxyEndpoint",
        providerCidrs: ["192.0.2.0/24"],
        resolvers: ["192.0.2.53/32"],
      },
      expectPosture: "ProviderOnly",
    },
    {
      name: "שרתי ספק בלי כתובות",
      options: { enabled: true, mode: "proxyEndpoint" },
      expectPosture: "LockedDown",
    },
  ].map((c) => {
    const rule = buildEgressRule(c.options as never);

    return { ...c, rule, description: describeEgress(rule) };
  }),
};

writeFileSync(path, JSON.stringify(vectors, null, 2) + "\n", "utf8");

console.log(`נכתבו ${(vectors["egress"] as { cases: unknown[] }).cases.length} מקרים.`);
