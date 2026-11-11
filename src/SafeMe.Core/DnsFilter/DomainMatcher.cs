namespace SafeMe.Core.DnsFilter;

/// <summary>
/// התאמת שם לרשימת דומיינים.
///
/// ההתאמה היא לפי תוויות שלמות ולא לפי סיומת טקסט: "example.com"
/// מתיר את "a.example.com" ואינו מתיר את "notexample.com". ההבדל
/// הזה הוא כל ההבדל בין רשימה לבנה לבין פרצה.
/// </summary>
public sealed class DomainMatcher
{
    public static readonly DomainMatcher Empty = new([]);

    private readonly HashSet<string> _domains;

    public DomainMatcher(IEnumerable<string> domains)
    {
        _domains = new HashSet<string>(StringComparer.Ordinal);

        foreach (var raw in domains)
        {
            if (Normalize(raw) is { } domain)
                _domains.Add(domain);
        }
    }

    public int Count => _domains.Count;

    /// <summary>
    /// מנרמל שם: אותיות קטנות, בלי נקודה בסוף, בלי "*." בהתחלה.
    /// מחזיר null לשם שאינו יכול להיות דומיין.
    ///
    /// שם בן תווית אחת נדחה. "com" ברשימה היה מתיר חצי מהאינטרנט,
    /// וזו טעות הקלדה שאסור שתהיה לה משמעות.
    /// </summary>
    public static string? Normalize(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;

        var name = raw.Trim().TrimEnd('.').ToLowerInvariant();

        if (name.StartsWith("*.", StringComparison.Ordinal)) name = name[2..];

        if (name.Length is 0 or > 253) return null;
        if (!name.Contains('.')) return null;

        foreach (var label in name.Split('.'))
        {
            if (label.Length is 0 or > 63) return null;

            foreach (var c in label)
            {
                var ok = c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_';

                if (!ok) return null;
            }
        }

        return name;
    }

    /// <summary>האם השם הוא אחד הדומיינים, או יושב מתחת לאחד מהם.</summary>
    public bool Matches(string? name)
    {
        if (_domains.Count == 0 || string.IsNullOrEmpty(name)) return false;

        var candidate = name.TrimEnd('.').ToLowerInvariant();

        while (true)
        {
            if (_domains.Contains(candidate)) return true;

            var dot = candidate.IndexOf('.');

            if (dot < 0) return false;

            candidate = candidate[(dot + 1)..];
        }
    }
}
