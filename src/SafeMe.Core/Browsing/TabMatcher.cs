namespace SafeMe.Core.Browsing;

/// <summary>לשונית פתוחה, כפי שנקראה מהדפדפן.</summary>
public sealed record OpenTab
{
    /// <summary>הדפדפן שבו היא פתוחה, לתצוגה בלבד.</summary>
    public required string Browser { get; init; }

    /// <summary>כותרת הלשונית. תמיד זמינה.</summary>
    public required string Title { get; init; }

    /// <summary>
    /// שם המארח, כשהצלחנו לקרוא אותו.
    ///
    /// null הוא המצב השכיח: כותרת זמינה בכל לשונית, אך הכתובת רק
    /// בפעילה — וגם שם רק כשהדפדפן חושף אותה לנגישות.
    /// </summary>
    public string? Host { get; init; }
}

/// <summary>מה נמצא, ולמה.</summary>
public sealed record TabMatch(OpenTab Tab, string Rule, bool ByHost);

/// <summary>
/// משווה לשוניות פתוחות מול רשימת חסימה.
///
/// זו אינה חסימה הרמטית, ואסור להציג אותה ככזו. היא רואה מה נפתח
/// אחרי שנפתח, אינה רואה גלישה בחלון פרטי בכל הדפדפנים, ומי שיודע
/// מה הוא עושה יעקוף אותה. היא קיימת בשביל המקרה שבו אין ספק סינון
/// כלל — ושם היא ההבדל בין משהו לכלום.
///
/// ההבחנה המרכזית כאן היא בין מארח לכותרת, והיא לא ניואנס:
///
///   מארח   עובדה. "chatgpt.com" הוא האתר, נקודה.
///   כותרת  טקסט חופשי שהאתר בוחר. מאמר בעיתון על הימורים נושא
///          את המילה "הימורים", והוא לא אתר הימורים.
///
/// לכן התאמה על כותרת דורשת ביטוי ארוך יותר ומסומנת בנפרד — כדי
/// שההורה יראה על מה ההתראה מבוססת, ולא יקבל אזהרה על כתבה שהילד
/// קרא בחדשות.
/// </summary>
public static class TabMatcher
{
    /// <summary>
    /// האורך המזערי לביטוי שמותר להתאים בכותרת.
    ///
    /// מילה קצרה מדי תופיע בכל דבר. "ai" לבדו מופיע ב"Mail", ב"Chair"
    /// וב"Israeli" — ובעברית קצר עוד יותר מסוכן.
    /// </summary>
    public const int MinTitleTermLength = 4;

    /// <summary>
    /// מוצא התאמות. מחזיר רשימה ריקה כשאין.
    ///
    /// כל התאמה מוחזרת בנפרד ולא רק הראשונה, כי ההורה רוצה לדעת מה
    /// היה פתוח ולא רק שמשהו היה.
    /// </summary>
    public static IReadOnlyList<TabMatch> Match(
        IEnumerable<OpenTab> tabs,
        IReadOnlyList<string> blockedHosts,
        IReadOnlyList<string> blockedTitleTerms)
    {
        ArgumentNullException.ThrowIfNull(tabs);

        var found = new List<TabMatch>();

        foreach (var tab in tabs)
        {
            var host = MatchHost(tab.Host, blockedHosts);

            if (host is not null)
            {
                found.Add(new TabMatch(tab, host, ByHost: true));
                continue;
            }

            /*
             * כותרת נבדקת רק כשאין מארח.
             *
             * כשהמארח ידוע והוא אינו ברשימה, זו תשובה — והתאמה על
             * הכותרת אחריה הייתה מייצרת התראה על אתר שהוכח שהוא
             * מותר. שתי ראיות שסותרות זו את זו, והחזקה מפסידה.
             */
            if (tab.Host is not null) continue;

            var term = MatchTitle(tab.Title, blockedTitleTerms);

            if (term is not null) found.Add(new TabMatch(tab, term, ByHost: false));
        }

        return found;
    }

    /// <summary>
    /// התאמת מארח, כולל תת-דומיינים.
    ///
    /// "openai.com" תופס גם "chat.openai.com", אך לא "notopenai.com" —
    /// ההשוואה היא על גבול נקודה ולא על הכלה במחרוזת. בלי זה, חסימת
    /// "ai.com" הייתה חוסמת חצי מהאינטרנט.
    /// </summary>
    private static string? MatchHost(string? host, IReadOnlyList<string> blocked)
    {
        if (host is null) return null;

        var clean = host.Trim().TrimEnd('.').ToLowerInvariant();

        if (clean.StartsWith("www.", StringComparison.Ordinal)) clean = clean[4..];

        foreach (var rule in blocked)
        {
            var needle = rule.Trim().TrimStart('.').ToLowerInvariant();

            if (needle.Length == 0) continue;

            if (clean == needle || clean.EndsWith("." + needle, StringComparison.Ordinal))
                return rule;
        }

        return null;
    }

    private static string? MatchTitle(string title, IReadOnlyList<string> terms)
    {
        foreach (var term in terms)
        {
            var needle = term.Trim();

            // ביטוי קצר מדי נדחה ולא מותאם. הוא היה תופס הכול.
            if (needle.Length < MinTitleTermLength) continue;

            if (title.Contains(needle, StringComparison.OrdinalIgnoreCase)) return term;
        }

        return null;
    }
}
