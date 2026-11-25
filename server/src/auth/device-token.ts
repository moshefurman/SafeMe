import { createHash, randomUUID } from "node:crypto";
import { SignJWT, jwtVerify } from "jose";

/**
 * אסימוני מחשב.
 *
 * נפרדים לחלוטין ממפתח חתימת המדיניות: אסימון גנוב מאפשר להתחזות
 * למחשב אחד ולשלוח פעימות שקריות, אך לא לחתום על מדיניות מקלה.
 * זו הסיבה שהם משתמשים בסוד סימטרי ולא במפתח ה-KMS.
 */

export interface DeviceClaims {
  deviceId: string;
  tenantId: string;
  hwid: string;
  jti: string;
  expiresAt: Date;
}

const ISSUER = "filterplus-server";
const AUDIENCE = "filterplus-agent";

function secretKey(secret: string): Uint8Array {
  // גזירה ל-32 בתים, כדי שסוד באורך שרירותי יתאים ל-HS256
  return createHash("sha256").update(secret).digest();
}

export async function issueDeviceToken(
  secret: string,
  ttlDays: number,
  claims: { deviceId: string; tenantId: string; hwid: string },
): Promise<{ token: string; jti: string; expiresAt: Date }> {
  const jti = randomUUID();
  const expiresAt = new Date(Date.now() + ttlDays * 24 * 60 * 60 * 1000);

  const token = await new SignJWT({
    tid: claims.tenantId,
    hwid: claims.hwid,
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setSubject(claims.deviceId)
    .setJti(jti)
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(Math.floor(expiresAt.getTime() / 1000))
    .sign(secretKey(secret));

  return { token, jti, expiresAt };
}

export async function verifyDeviceToken(
  secret: string,
  token: string,
): Promise<DeviceClaims | null> {
  try {
    const { payload } = await jwtVerify(token, secretKey(secret), {
      issuer: ISSUER,
      audience: AUDIENCE,
    });

    if (!payload.sub || !payload.jti || typeof payload["tid"] !== "string") return null;
    if (typeof payload["hwid"] !== "string") return null;

    return {
      deviceId: payload.sub,
      tenantId: payload["tid"],
      hwid: payload["hwid"],
      jti: payload.jti,
      expiresAt: new Date((payload.exp ?? 0) * 1000),
    };
  } catch {
    // חתימה שגויה, פג תוקף, או אסימון פגום — כולם מטופלים זהה
    return null;
  }
}

/** אסימוני רישום נשמרים כ-hash בלבד, בדיוק כמו סיסמאות. */
export function hashEnrollToken(token: string): Buffer {
  return createHash("sha256").update(token.trim().toUpperCase(), "utf8").digest();
}
