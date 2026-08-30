using System.Text.Json;

namespace SafeMe.Core.Models;

/// <summary>
/// מי מספק את האינטרנט בפועל, ברגע זה.
///
/// נוסף אחרי שהתברר שרשת אלחוטית לבדה אינה זהות מספקת: אותו נתב,
/// אותו שם, אותה כתובת חומרה — וקו אחר מאחוריו. מי שהחליף את הקו
/// המסונן בקו פתוח לא שינה דבר שהסוכן ידע להסתכל עליו.
///
/// לכן האישור הוא לצירוף: רשת אלחוטית וספק. אישור ל"הרשת בבית"
/// אינו אמור לכסות את "הנתב בבית, מנותב עכשיו דרך קו לא מסונן".
/// </summary>
public sealed record IspIdentity(int? Asn, string? Name)
{
    /// <summary>
    /// המזהה שנשמר ומושווה.
    ///
    /// מספר ה-ASN ולא השם: השם הוא טקסט חופשי שמשתנה עם מיתוג,
    /// עם פיסוק, ועם מי שהקליד אותו במאגר. המספר מוקצה, יציב,
    /// ומזהה את הרשת האוטונומית עצמה.
    ///
    /// כשאין מספר נופלים לשם — עדיף זיהוי חלש על פני שום זיהוי.
    /// </summary>
    public string? Key => Asn is { } asn ? $"AS{asn}" : Name;

    public bool IsKnown => Asn is not null || !string.IsNullOrWhiteSpace(Name);

    /// <summary>ריק. לא "ספק לא ידוע", אלא היעדר ידיעה.</summary>
    public static readonly IspIdentity Unknown = new(null, null);

    /// <summary>
    /// קורא את תשובת ipinfo.io.
    ///
    /// נמדד מרשת ללא סינון:
    ///
    ///   {"ip":"...","org":"AS51825 Telzar 019 International Telecommunications
    ///    Services LTD","country":"IL", ...}
    ///
    /// אין שם שדה isp — יש org, ובו מספר ה-ASN ושם הספק דבוקים
    /// זה לזה. הפירוק כאן, ולא במקום שקורא מהרשת, כדי שאפשר יהיה
    /// לבדוק אותו בלי לצאת החוצה.
    /// </summary>
    public static IspIdentity Read(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Unknown;

        try
        {
            using var document = JsonDocument.Parse(json);

            if (!document.RootElement.TryGetProperty("org", out var org) ||
                org.ValueKind != JsonValueKind.String)
                return Unknown;

            return Parse(org.GetString());
        }
        catch (JsonException)
        {
            return Unknown;
        }
    }

    /// <summary>
    /// מפריד "AS51825 Telzar 019 ..." למספר ולשם.
    ///
    /// המספר הוא הקידומת בלבד. "AS51825" בתוך שם הספק אינו קידומת,
    /// ו-"Telzar 019" מתחיל במילה ולא במספר — שני המקרים נופלים
    /// לשם המלא, וזו התשובה הנכונה עבורם.
    /// </summary>
    public static IspIdentity Parse(string? org)
    {
        if (string.IsNullOrWhiteSpace(org)) return Unknown;

        var text = org.Trim();

        if (text.StartsWith("AS", StringComparison.OrdinalIgnoreCase))
        {
            var space = text.IndexOf(' ');
            var digits = space < 0 ? text[2..] : text[2..space];

            if (digits.Length > 0 && int.TryParse(digits, out var asn))
            {
                var name = space < 0 ? null : text[(space + 1)..].Trim();

                return new IspIdentity(asn, string.IsNullOrWhiteSpace(name) ? null : name);
            }
        }

        return new IspIdentity(null, text);
    }
}
