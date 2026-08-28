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

/*
 * הצעת עדכון, בצורה שהשרת שולח בפועל.
 *
 * החוזה הזה כבר נשבר פעם אחת בשקט: השרת שלח updatePublicKeyPem מאז
 * שהמנגנון נבנה, והסוכן לא הכיר את השדה וזרק אותו. שני הצדדים היו
 * כתובים, ושום דבר לא עבד.
 */
vectors["updateOffer"] = {
  version: "1.1.2",
  downloadUrl:
    "https://github.com/moshefurman/safeme-releases/releases/download/v1.1.2/SafeMe-Setup.exe",
  sha256: "b4cb572b423663bfe9f3c34acc1d5191a535c57393765c0e7bb138d8c3b6d515",
  sizeBytes: 64471662,
  hwidHash: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
  issuedUtc: "2026-08-28T12:00:00.000Z",
  expiresUtc: "2026-08-28T12:30:00.000Z",
};


writeFileSync(path, JSON.stringify(vectors, null, 2) + "\n", "utf8");

console.log(`נכתבו ${(vectors["egress"] as { cases: unknown[] }).cases.length} מקרים.`);
