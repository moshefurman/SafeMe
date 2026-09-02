import { useEffect, useState } from "react";

import { api } from "../api";

/*
 * כתובת הפניות, נטענת פעם אחת לכל טעינת דף.
 *
 * ברמת המודול ולא ב-state של רכיב: היא זהה לכולם ואינה משתנה
 * תוך כדי, ושלושה רכיבים שכל אחד מושך אותה בנפרד הם שלוש בקשות
 * לאותה מחרוזת.
 */
let cached: string | null | undefined;
let inflight: Promise<string | null> | null = null;

async function loadSupportEmail(): Promise<string | null> {
  if (cached !== undefined) return cached;

  inflight ??= api
    .get<{ email: string | null }>("/api/portal/v1/support")
    .then((r) => (cached = r.email))
    .catch(() => (cached = null))
    .finally(() => { inflight = null; });

  return inflight;
}

/**
 * "פנו אלינו" — עם כתובת.
 *
 * הפורטל אמר להורה "יש לפנות למוקד" ולא אמר איך. זה מבוי סתום
 * בדיוק ברגע שבו הוא הכי צריך עזרה: הוא רוצה להסיר את התוכנה,
 * או שהחשבון שלו מושעה, ואין לו למי לכתוב.
 *
 * כשלא הוגדרה כתובת הרכיב אינו מציג דבר. משפט "פנו לתמיכה" בלי
 * יעד גרוע מכלום — הוא נראה כמו מוצא ואינו כזה.
 */
export function SupportLink({ prefix }: { prefix?: string }): JSX.Element | null {
  const [email, setEmail] = useState<string | null>(cached ?? null);

  useEffect(() => {
    let alive = true;

    void loadSupportEmail().then((value) => { if (alive) setEmail(value); });

    return () => { alive = false; };
  }, []);

  if (email === null) return null;

  return (
    <p className="muted small">
      {prefix ?? "לפניות ושאלות:"}{" "}
      <a className="link" href={`mailto:${email}`} dir="ltr">{email}</a>
    </p>
  );
}
