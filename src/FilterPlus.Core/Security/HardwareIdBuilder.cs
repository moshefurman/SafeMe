using System.Security.Cryptography;
using System.Text;

namespace FilterPlus.Core.Security;

/// <summary>
/// בונה מזהה חומרה יציב מרכיבי חומרה. הלוגיקה טהורה וניתנת לבדיקה;
/// איסוף הרכיבים עצמם מתבצע ב-FilterPlus.Service (WMI ורג'יסטרי).
///
/// עקרון: משתמשים רק ברכיבים שאינם משתנים בהחלפת דיסק או כרטיס רשת,
/// כדי שלא ינותקו רישיונות בטעות.
/// </summary>
public static class HardwareIdBuilder
{
    /// <summary>אורך המזהה בתווי Base32.</summary>
    public const int IdLength = 26;

    private static readonly string[] PlaceholderValues =
    [
        "to be filled by o.e.m.",
        "system serial number",
        "default string",
        "none",
        "n/a",
        "not specified",
        "00000000-0000-0000-0000-000000000000",
        "ffffffff-ffff-ffff-ffff-ffffffffffff"
    ];

    /// <summary>
    /// מרכיב מזהה מרשימת רכיבים. רכיבים ריקים או ערכי ברירת מחדל של יצרנים
    /// מסוננים החוצה כדי שלא ייצרו התנגשות בין מחשבים שונים.
    /// </summary>
    public static string Build(IEnumerable<string?> components)
    {
        var normalized = components
            .Select(Normalize)
            .Where(v => v is not null)
            .Select(v => v!)
            .ToArray();

        if (normalized.Length == 0)
            throw new InvalidOperationException("לא נמצא אף רכיב חומרה יציב לבניית מזהה.");

        var material = string.Join('|', normalized);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(material));

        return Base32Crockford.Encode(hash)[..IdLength];
    }

    /// <summary>מנרמל ערך רכיב, ומחזיר null אם הערך חסר משמעות.</summary>
    public static string? Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;

        var trimmed = value.Trim();

        if (PlaceholderValues.Contains(trimmed, StringComparer.OrdinalIgnoreCase)) return null;
        if (trimmed.All(c => c == '0' || c == '-' || c == ' ')) return null;
        if (trimmed.Length < 4) return null;

        return trimmed.ToUpperInvariant();
    }
}
