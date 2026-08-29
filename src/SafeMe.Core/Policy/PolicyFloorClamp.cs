using SafeMe.Core.Models;

namespace SafeMe.Core.Policy;

/// <summary>מה השתנה כשמדיניות הוצמדה לרצפה.</summary>
public sealed record ClampResult
{
    public required PolicyBundle Policy { get; init; }

    /// <summary>הצירים שהועלו בחזרה לרצפה. ריק כשהמדיניות עמדה בה מלכתחילה.</summary>
    public IReadOnlyList<string> Raised { get; init; } = [];

    public bool WasClamped => Raised.Count > 0;
}

/// <summary>
/// מצמיד מדיניות לרצפת המחשב במקום לדחות אותה.
///
/// זה תיקון של כשל תכנוני שעלה ימים לאבחן, והוא שווה הסבר מלא.
///
/// המחגר נכון: מדיניות אינה יכולה להוריד את האכיפה מתחת למה שנקבע
/// ברישום. אבל התגובה הקודמת להפרה הייתה **לדחות את החבילה כולה** —
/// וחבילת המדיניות אינה רק רמת אכיפה. היא נושאת גם את כללי הזיהוי
/// של ספקי הסינון, ובלעדיהם המחשב אינו יודע לזהות אף ספק ומדווח
/// "לא מסונן" על מחשב מסונן לחלוטין.
///
/// כך נוצר מבוי סתום: המחשב דחה כל חבילה, לא קיבל כללי זיהוי, ולכן
/// לא יכול היה להוכיח שהוא מסונן — והדרך היחידה החוצה הייתה הסרה
/// והתקנה מחדש. שדה אחד שלא תאם גרם לזריקת כל השאר.
///
/// ההצמדה שומרת על המחגר במלואו: הצירים שהמדיניות ניסתה להקל מועלים
/// בחזרה לרצפה, ומה שאינו נוגע לרצפה — כללי הזיהוי, הגששים, רשימות
/// ההיתר — מוחל כרגיל. שרת פרוץ עדיין אינו יכול להוריד אכיפה, וזו
/// כל ההבטחה שהמחגר נועד לתת.
/// </summary>
public static class PolicyFloorClamp
{
    /// <summary>
    /// מחזיר עותק שאינו נמוך מהרצפה. אינו משנה את המקור.
    /// </summary>
    public static ClampResult Apply(PolicyBundle policy, PolicyFloorSpec floor)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(floor);

        var e = policy.Enforcement;
        var raised = new List<string>();

        var mode = (EnforcementMode)Math.Max((int)e.Mode, (int)floor.Mode);
        var action = (RedAction)Math.Max((int)e.OnRedAction, (int)floor.OnRedAction);
        var green = Math.Max(e.MinScoreForGreen, floor.MinScoreForGreen);
        var yellow = Math.Max(e.MinScoreForYellow, floor.MinScoreForYellow);

        if (mode != e.Mode) raised.Add($"מצב האכיפה הועלה מ-{e.Mode} ל-{mode}");
        if (action != e.OnRedAction) raised.Add($"הפעולה במצב אדום הועלתה מ-{e.OnRedAction} ל-{action}");
        if (green != e.MinScoreForGreen) raised.Add($"סף הציון הירוק הועלה ל-{green}");
        if (yellow != e.MinScoreForYellow) raised.Add($"סף הציון הצהוב הועלה ל-{yellow}");

        var providers = ClampProviders(e.AllowedNetworks.RequireProvider, floor.RequireProvider, raised);

        if (raised.Count == 0) return new ClampResult { Policy = policy };

        /*
         * הרשימות מועברות בהפניה ולא משוכפלות: הן אינן משתנות אחרי
         * הפענוח, ושכפולן היה עולה בלי להוסיף דבר.
         *
         * החתימה **אינה** מועברת. היא נחתמה על גוף אחר מזה שיצא מכאן,
         * ושדה חתימה שאינו מאמת את מה שהוא יושב עליו הוא מלכודת למי
         * שיקרא את הקובץ בעתיד ויניח שאפשר לסמוך עליו.
         */
        return new ClampResult
        {
            Raised = raised,
            Policy = new PolicyBundle
            {
                Version = policy.Version,
                IssuedUtc = policy.IssuedUtc,
                TtlMinutes = policy.TtlMinutes,
                GraceMinutes = policy.GraceMinutes,
                Signature = null,
                Providers = policy.Providers,
                ContentProbes = policy.ContentProbes,
                AiProbes = policy.AiProbes,
                ImageProbes = policy.ImageProbes,
                Enforcement = new EnforcementPolicy
                {
                    Mode = mode,
                    OnRedAction = action,
                    MinScoreForGreen = green,
                    MinScoreForYellow = yellow,
                    LockoutGraceSeconds = e.LockoutGraceSeconds,
                    AlwaysAllow = e.AlwaysAllow,
                    Schedules = e.Schedules,
                    Egress = e.Egress,
                    AllowedNetworks = new AllowedNetworks
                    {
                        WifiSsids = e.AllowedNetworks.WifiSsids,
                        Cidrs = e.AllowedNetworks.Cidrs,
                        RequireProvider = providers
                    }
                }
            }
        };
    }

    /// <summary>
    /// רשימת הספקים המאושרים.
    ///
    /// רשימה ריקה משמעה "אין דרישת ספק" — כלומר כל רשת מתקבלת — ולכן
    /// היא המצב המקל ביותר, וכל ספק שנוסף לרשימה מרחיב את מה שמתקבל.
    /// רצפה ריקה אינה מגבילה דבר ומשאירה את הרשימה כפי שהיא.
    /// </summary>
    private static List<string> ClampProviders(
        List<string> candidate, List<string> floor, List<string> raised)
    {
        if (floor.Count == 0) return candidate;

        var allowed = candidate
            .Where(p => floor.Contains(p, StringComparer.OrdinalIgnoreCase))
            .ToList();

        // ביטול מוחלט של הדרישה מחזיר את רשימת הרצפה, ולא רשימה ריקה
        // שמשמעה "הכול מתקבל".
        if (allowed.Count == 0) allowed = [.. floor];

        var dropped = candidate
            .Where(p => !floor.Contains(p, StringComparer.OrdinalIgnoreCase))
            .ToList();

        if (dropped.Count > 0)
            raised.Add($"ספקים שאינם ברצפה הוסרו: {string.Join(", ", dropped)}");
        else if (candidate.Count == 0)
            raised.Add($"דרישת הספק הוחזרה: {string.Join(", ", allowed)}");

        return allowed;
    }
}
