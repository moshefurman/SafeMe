using FilterPlus.Core.Models;
using FilterPlus.Core.Policy;

namespace FilterPlus.Core.Audit;

/// <summary>
/// ממיר אוסף תוצאות גששים לציון 0-100 ולסטטוס תצוגה.
/// לוגיקה טהורה, ללא תלות ברשת, כדי שתהיה ניתנת לבדיקת יחידה.
/// </summary>
public static class ScoreCalculator
{
    /// <summary>תקרת ציון כאשר נכשל גשש בחומרה קריטית.</summary>
    public const int CriticalFailureCeiling = 40;

    public static int ComputeScore(IReadOnlyList<ProbeResult> results)
    {
        // גששים ללא הכרעה (שגיאת רשת, timeout) אינם נספרים בשני הכיוונים
        var counted = results.Where(r => r.Outcome != ProbeOutcome.Inconclusive && r.Weight > 0).ToList();

        if (counted.Count == 0) return 0;

        var totalWeight = counted.Sum(r => r.Weight);

        // הסכימה היא על מה שנזקף ולא על מי שעבר, כדי שראיה חלקית
        // תתרום את חלקה במקום להתאפס
        var earned = counted.Sum(r => r.Credit);
        var score = (int)Math.Round(100.0 * earned / totalWeight, MidpointRounding.AwayFromZero);

        var hasCriticalFailure = counted.Any(r =>
            r.Outcome == ProbeOutcome.Fail && r.Severity == ProbeSeverity.Critical);

        if (hasCriticalFailure)
            score = Math.Min(score, CriticalFailureCeiling);

        return Math.Clamp(score, 0, 100);
    }

    public static SecurityStatus ResolveStatus(
        int score, ProviderDetection detection, EnforcementPolicy policy, bool lockoutActive)
    {
        if (lockoutActive) return SecurityStatus.Blocked;

        /*
         * בדיקה שלא רצה אינה בדיקה שנכשלה.
         *
         * בלי ההבחנה הזו, מחשב בלי רשת מדווח "אינו מסונן", נחסם,
         * ואז לעולם לא יוכל לבדוק שוב — כי הבדיקה עצמה זקוקה
         * לרשת. זה נעל מחשב אמיתי, פעמיים.
         */
        if (!detection.DetectionRan) return SecurityStatus.Unknown;

        var providerKnown = detection.ProviderId is not null && detection.Trust >= TrustLevel.Medium;

        if (providerKnown && detection.Trust == TrustLevel.High && score >= policy.MinScoreForGreen)
            return SecurityStatus.Safe;

        if (providerKnown && score >= policy.MinScoreForYellow)
            return SecurityStatus.LowFilter;

        return SecurityStatus.Unfiltered;
    }

    /// <summary>מנסח כותרת קצרה בעברית שמוצגת ב-Tooltip ובחלון הסטטוס.</summary>
    public static string BuildHeadline(SecurityStatus status, ProviderDetection detection, int score) => status switch
    {
        SecurityStatus.Safe =>
            $"החיבור מסונן דרך {detection.DisplayName ?? detection.ProviderId} (ציון {score})",

        // זיהוי בווקטור אחד אינו "בדיקה שנכשלה" אלא ראיה חלקית,
        // וניסוח שמדבר על כשלים שולח את ההורה לחפש תקלה שאינה קיימת
        SecurityStatus.LowFilter when detection.ProviderId is not null && detection.MatchCount == 1 =>
            $"החיבור מסונן דרך {detection.DisplayName ?? detection.ProviderId}, "
            + $"אך זוהה בדרך אחת בלבד ({string.Join(", ", detection.MatchedVectors)}).",

        SecurityStatus.LowFilter =>
            $"הסינון פעיל אבל חלקי (ציון {score}). חלק מהבדיקות נכשלו.",

        SecurityStatus.Unfiltered => detection.ProviderId is null
            ? "לא זוהה ספק סינון מאושר. החיבור לא מוגן."
            : $"הסינון לא עומד בדרישות (ציון {score}).",

        SecurityStatus.Blocked =>
            "נעילת חירום פעילה. החיבור חסום, חוץ מהקשר עם FilterPlus.",

        _ => "בודק את מצב החיבור…"
    };

    /// <summary>
    /// מכריע את זהות הספק: נדרשות שתי התאמות מווקטורים חיים שונים
    /// לרמת ביטחון גבוהה. התאמה בודדת נותנת ביטחון בינוני, ואפס
    /// התאמות משמען ספק לא מזוהה.
    ///
    /// תעודת השורש אינה נספרת. היא נשארת מותקנת גם כשהספק כבר לא
    /// שם, ולכן אינה יכולה להעיד על ההווה. התפקיד היחיד שנשאר לה
    /// כאן הוא וטו, וגם הוא רק בכיוון אחד.
    /// </summary>
    public static TrustLevel ResolveTrust(ProviderDetection detection, ProviderRule? rule)
    {
        if (detection.MatchCount == 0) return TrustLevel.None;

        /*
         * הווטו.
         *
         * ספק שהמדיניות דורשת את תעודתו, וההתקנה חסרה — משהו שם
         * אינו כפי שהוגדר, ואין לטעון לביטחון גבוה. זה נשאר גם
         * כשהמשקל אפס, מפני שוטו יכול רק להוריד את הטענה להגנה,
         * לעולם לא להעלות אותה. זה ההבדל בין ראיה לבין תנאי.
         */
        if (rule?.RootCa is { Required: true } && !detection.RootCaMatch)
            return TrustLevel.Low;

        var trust = detection.MatchCount >= 2 ? TrustLevel.High : TrustLevel.Medium;

        // רמת האמון לעולם אינה עולה על זו שהוגדרה במדיניות עבור הספק
        return rule is null ? trust : (TrustLevel)Math.Min((int)trust, (int)rule.TrustLevel);
    }
}
