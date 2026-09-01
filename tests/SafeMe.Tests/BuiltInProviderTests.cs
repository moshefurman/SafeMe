using SafeMe.Core.Policy;
using SafeMe.Service.Audit;

namespace SafeMe.Tests;

/// <summary>
/// כללי הזיהוי שנוסעים עם הסוכן.
///
/// עד כה כל כלל הגיע מהשרת, ורשימה ריקה לא נראתה כמו "אינני יודע"
/// אלא כמו "לא זוהה ספק מאושר" — כלומר כמו מחשב לא מסונן. סוכן
/// שהותקן בלי לקבל מדיניות הכריז שהחיבור אינו מסונן בזמן שהמשתמש
/// גלש דרך רימון.
///
/// זה הכיוון הגרוע מבין השניים: הוא גורר אזהרה, ובמצב אכיפה גם
/// חסימה, על מחשב מוגן לחלוטין.
/// </summary>
public class BuiltInProviderTests
{
    [Fact]
    public void Default_policy_can_recognize_something()
    {
        var providers = PolicyBundle.CreateDefault().Providers;

        Assert.NotEmpty(providers);

        /*
         * כל כלל מוטבע חייב וקטור חי.
         *
         * כלל בלי דרך להתאים הוא רשומה שנראית כמו זיהוי ואינה
         * מזהה דבר — בדיוק המצב שהבדיקה הזו נועדה למנוע.
         */
        foreach (var p in providers)
        {
            Assert.False(string.IsNullOrWhiteSpace(p.Id));
            Assert.NotNull(p.TlsIssuer);
            Assert.NotEmpty(p.TlsIssuer!.Patterns);
            Assert.NotEmpty(p.TlsIssuer.Probes);
        }
    }

    /// <summary>
    /// המנפיקים האמיתיים, כפי שנמדדו מתוך הרשתות עצמן.
    ///
    /// לא מחרוזות שהומצאו לבדיקה: השורה של נטפרי הועתקה מתעודה
    /// שנצפתה בשטח. תבנית שתפסיק להתאים לה תיפול כאן, ולא אצל
    /// משתמש שרואה "אינו מסונן" בזמן שהוא מסונן.
    /// </summary>
    [Theory]
    [InlineData("netfree", "CN=\"NetFree Node Intermediate CA, 019 Telzar\"")]
    [InlineData("rimon", "CN=Rimon Internet CA, O=Rimon")]
    public void Built_in_patterns_match_real_issuers(string providerId, string issuer)
    {
        var rule = PolicyBundle.BuiltInProviders().Single(p => p.Id == providerId);

        Assert.Contains(rule.TlsIssuer!.Patterns, pattern => Wildcard.IsMatch(issuer, pattern));
    }

    [Fact]
    public void A_stranger_is_not_matched()
    {
        // ספק אקראי אינו אמור להתאים לאף כלל מוטבע
        const string issuer = "CN=R3, O=Let's Encrypt";

        foreach (var p in PolicyBundle.BuiltInProviders())
            Assert.DoesNotContain(p.TlsIssuer!.Patterns, x => Wildcard.IsMatch(issuer, x));
    }
}
