using SafeMe.Core.Models;

namespace SafeMe.Core.Policy;

/// <summary>
/// מדד ההחמרה של מדיניות, על חמישה צירים בלתי תלויים.
///
/// זהו הלב של מנגנון המחגר: שינוי מרחוק יכול רק להדק, לעולם לא לשחרר.
/// הסיווג מתבצע גם בשרת וגם כאן, במחשב. אילו התבצע בשרת בלבד, שרת פרוץ
/// היה מדלג עליו והמנגנון היה חסר ערך.
/// </summary>
public sealed record PolicyStrictness
{
    public required int Mode { get; init; }
    public required int OnRedAction { get; init; }
    public required int MinScoreForGreen { get; init; }
    public required int MinScoreForYellow { get; init; }

    /// <summary>הספקים המאושרים. רשימה ריקה משמעה שאין דרישת ספק כלל.</summary>
    public required IReadOnlySet<string> RequiredProviders { get; init; }

    /// <summary>משקל כל גשש. הסרת גשש או הפחתת משקלו הן הקלה.</summary>
    public required IReadOnlyDictionary<string, int> ProbeWeights { get; init; }

    public static PolicyStrictness FromPolicy(PolicyBundle policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        var enforcement = policy.Enforcement;

        var weights = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (var probe in policy.ContentProbes) weights[probe.Id] = probe.Weight;
        foreach (var probe in policy.AiProbes) weights[probe.Id] = probe.Weight;
        foreach (var probe in policy.ImageProbes) weights[probe.Id] = probe.Weight;

        return new PolicyStrictness
        {
            Mode = (int)enforcement.Mode,
            OnRedAction = (int)enforcement.OnRedAction,
            MinScoreForGreen = enforcement.MinScoreForGreen,
            MinScoreForYellow = enforcement.MinScoreForYellow,
            RequiredProviders = new HashSet<string>(
                enforcement.AllowedNetworks.RequireProvider, StringComparer.OrdinalIgnoreCase),
            ProbeWeights = weights
        };
    }

    /// <summary>הרצפה שמתקבלת מהשרת ברישום, לפני שיש מדיניות מלאה.</summary>
    public static PolicyStrictness Floor(
        EnforcementMode mode,
        RedAction onRedAction,
        int minScoreForGreen,
        int minScoreForYellow,
        IEnumerable<string>? requiredProviders = null) => new()
    {
        Mode = (int)mode,
        OnRedAction = (int)onRedAction,
        MinScoreForGreen = minScoreForGreen,
        MinScoreForYellow = minScoreForYellow,
        RequiredProviders = new HashSet<string>(
            requiredProviders ?? [], StringComparer.OrdinalIgnoreCase),
        ProbeWeights = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
    };
}

/// <summary>תוצאת ההשוואה בין שתי רמות החמרה.</summary>
public sealed record StrictnessDelta
{
    /// <summary>true אם ולו ציר אחד ירד. אין "החמרה נטו" שמקזזת.</summary>
    public bool IsLoosening => Reasons.Count > 0;

    public IReadOnlyList<string> Reasons { get; init; } = [];

    public static readonly StrictnessDelta None = new();
}

public static class StrictnessComparer
{
    /// <summary>
    /// בודק אם המעבר מ-from ל-to הוא הקלה.
    ///
    /// כלל ההכרעה: ירידה ולו בציר אחד מסווגת כהקלה, גם אם צירים אחרים
    /// הוחמרו. אחרת אפשר היה להקל בציר משמעותי ולהסוות בהחמרה זניחה.
    /// </summary>
    public static StrictnessDelta Compare(PolicyStrictness from, PolicyStrictness to)
    {
        ArgumentNullException.ThrowIfNull(from);
        ArgumentNullException.ThrowIfNull(to);

        var reasons = new List<string>();

        if (to.Mode < from.Mode)
            reasons.Add($"מצב האכיפה ירד מ-{(EnforcementMode)from.Mode} ל-{(EnforcementMode)to.Mode}");

        if (to.OnRedAction < from.OnRedAction)
            reasons.Add($"הפעולה במצב אדום ירדה מ-{(RedAction)from.OnRedAction} ל-{(RedAction)to.OnRedAction}");

        if (to.MinScoreForGreen < from.MinScoreForGreen)
            reasons.Add($"סף הציון הירוק ירד מ-{from.MinScoreForGreen} ל-{to.MinScoreForGreen}");

        if (to.MinScoreForYellow < from.MinScoreForYellow)
            reasons.Add($"סף הציון הצהוב ירד מ-{from.MinScoreForYellow} ל-{to.MinScoreForYellow}");

        // רשימה ריקה משמעה "אין דרישת ספק", ולכן היא המצב המקל ביותר.
        // מעבר מרשימה מוגדרת לרשימה ריקה הוא הקלה, גם אם טכנית זו תת-קבוצה.
        if (from.RequiredProviders.Count > 0 && to.RequiredProviders.Count == 0)
        {
            reasons.Add("דרישת הספק המאושר בוטלה");
        }
        else if (from.RequiredProviders.Count > 0)
        {
            /*
             * ההשוואה הזו רצה רק כשיש דרישה להשוות אליה.
             *
             * רשימה ריקה אינה "קבוצה ריקה" אלא היעדר דרישה — כלומר כל
             * הרשתות מתקבלות. מעבר ממנה לרשימה מוגדרת מצמצם את מה
             * שמתקבל, ולכן הוא החמרה. בלי התנאי הזה כל רצפה ללא דרישת
             * ספק הייתה דוחה כל מדיניות שמגדירה אחת — כלומר בדיוק את
             * ההידוק שהיא אמורה לאפשר.
             */
            var added = to.RequiredProviders.Except(from.RequiredProviders, StringComparer.OrdinalIgnoreCase).ToList();

            if (added.Count > 0)
                reasons.Add($"נוספו ספקים מאושרים: {string.Join(", ", added)}");
        }

        foreach (var (probeId, weight) in from.ProbeWeights)
        {
            if (!to.ProbeWeights.TryGetValue(probeId, out var newWeight))
            {
                reasons.Add($"הגשש {probeId} הוסר");
                continue;
            }

            if (newWeight < weight)
                reasons.Add($"משקל הגשש {probeId} ירד מ-{weight} ל-{newWeight}");
        }

        return reasons.Count == 0 ? StrictnessDelta.None : new StrictnessDelta { Reasons = reasons };
    }

    /// <summary>
    /// האם המדיניות המועמדת עומדת ברצפה או מעליה.
    ///
    /// מעל הרצפה כולם חופשיים לנוע בשני הכיוונים — כך ההורה יכול להחמיר
    /// זמנית ולחזור. רק ירידה מתחת לרצפה דורשת היתר חתום מהחברה.
    /// </summary>
    public static StrictnessDelta CheckAgainstFloor(PolicyStrictness floor, PolicyStrictness candidate) =>
        Compare(floor, candidate);
}
