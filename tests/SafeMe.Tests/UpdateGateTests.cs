using SafeMe.Core.Models;
using SafeMe.Core.Updates;

using Xunit;

namespace SafeMe.Tests;

/// <summary>
/// השער שלפני הרצת עדכון.
///
/// מה שנבדק כאן הוא הקוד שמחליט אם להריץ קובץ שהורד מהאינטרנט
/// בהרשאות SYSTEM. החתימה כבר אומתה כשהוא נקרא — אבל חתימה תקפה
/// על תוכן שגוי היא עדיין תוכן שגוי, וזה מה שהמחלקה הזו תופסת.
/// </summary>
public class UpdateGateTests
{
    private const string Hwid = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";
    private const string Digest = "b4cb572b423663bfe9f3c34acc1d5191a535c57393765c0e7bb138d8c3b6d515";

    private static readonly DateTimeOffset Now = new(2026, 8, 28, 12, 0, 0, TimeSpan.Zero);

    private static UpdateOffer Offer(Action<UpdateOffer>? tweak = null)
    {
        var offer = new UpdateOffer
        {
            Version = "1.1.2",
            DownloadUrl = "https://github.com/x/y/releases/download/v1.1.2/SafeMe-Setup.exe",
            Sha256 = Digest,
            SizeBytes = 64_471_662,
            HwidHash = Hwid,
            IssuedUtc = Now.AddMinutes(-1),
            ExpiresUtc = Now.AddMinutes(29),
        };

        tweak?.Invoke(offer);

        return offer;
    }

    private static UpdateVerdict Judge(UpdateOffer offer, string current = "1.1.1")
        => UpdateGate.Evaluate(offer, current, Hwid, Now);

    // ─────────────────────────────────────────────── המסלול התקין

    [Fact]
    public void A_sound_offer_is_accepted()
    {
        var verdict = Judge(Offer());

        Assert.True(verdict.Accepted);
        Assert.Equal(UpdateRejection.None, verdict.Reason);
    }

    // ─────────────────────────────────────────────── למי ההצעה נועדה

    [Fact]
    public void An_offer_for_another_device_is_refused()
    {
        // הצורה הפשוטה ביותר של תקיפה כאן: ללכוד הצעה תקפה
        // וחתומה, ולשדר אותה למחשב אחר.
        var verdict = Judge(Offer(o => o.HwidHash = new string('f', 64)));

        Assert.False(verdict.Accepted);
        Assert.Equal(UpdateRejection.WrongDevice, verdict.Reason);
    }

    [Fact]
    public void The_device_match_ignores_case()
    {
        var verdict = Judge(Offer(o => o.HwidHash = Hwid.ToUpperInvariant()));

        Assert.True(verdict.Accepted);
    }

    // ─────────────────────────────────────────────── תוקף

    [Fact]
    public void An_expired_offer_is_refused()
    {
        var verdict = Judge(Offer(o => o.ExpiresUtc = Now.AddMinutes(-10)));

        Assert.Equal(UpdateRejection.Expired, verdict.Reason);
    }

    [Fact]
    public void A_small_clock_drift_does_not_refuse()
    {
        // שעון מקומי שזז בדקות הוא מצב רגיל. דחייה בגללו הייתה
        // משביתה עדכונים במחשבים שלמים בלי סיבה.
        var verdict = Judge(Offer(o => o.ExpiresUtc = Now.AddMinutes(-2)));

        Assert.True(verdict.Accepted);
    }

    [Fact]
    public void An_offer_signed_in_the_future_is_refused()
    {
        // אינה בהכרח זדונית — שעון שזז אחורה מייצר אותה — אבל
        // קבלתה הייתה מרחיבה את חלון החיים של כל הצעה שנלכדה.
        var verdict = Judge(Offer(o => o.IssuedUtc = Now.AddHours(2)));

        Assert.Equal(UpdateRejection.Expired, verdict.Reason);
    }

    // ─────────────────────────────────────────────── ירידת גרסה

    [Theory]
    [InlineData("1.1.1", "1.1.1")]
    [InlineData("1.1.0", "1.1.1")]
    [InlineData("1.0.9", "1.1.1")]
    [InlineData("0.9.9", "1.0.0")]
    public void An_offer_that_is_not_newer_is_refused(string offered, string current)
    {
        /*
         * זו ההגנה מפני החזרת המחשב לגרסה ישנה עם פגם ידוע —
         * תקיפה שאינה דורשת לפרוץ לשרת אלא רק לשמור הצעה ישנה
         * ולשדר אותה שוב.
         */
        var verdict = Judge(Offer(o => o.Version = offered), current);

        Assert.False(verdict.Accepted);
        Assert.Equal(UpdateRejection.NotNewer, verdict.Reason);
    }

    [Fact]
    public void Version_comparison_is_numeric_not_textual()
    {
        // "1.10.0" קטן מ-"1.9.0" לקסיקוגרפית, וזה ההפך מהנכון.
        var verdict = Judge(Offer(o => o.Version = "1.10.0"), "1.9.0");

        Assert.True(verdict.Accepted);
    }

    [Theory]
    [InlineData("1.1")]
    [InlineData("1.1.1.1")]
    [InlineData("v1.1.1")]
    [InlineData("")]
    [InlineData("אחת")]
    public void An_unparsable_version_is_refused(string version)
    {
        var verdict = Judge(Offer(o => o.Version = version));

        Assert.Equal(UpdateRejection.BadVersion, verdict.Reason);
    }

    [Fact]
    public void Three_digit_patch_numbers_work()
    {
        // הספרור שנבחר הוא 1.1.1 עד 1.1.999
        var verdict = Judge(Offer(o => o.Version = "1.1.999"), "1.1.998");

        Assert.True(verdict.Accepted);
    }

    // ─────────────────────────────────────────────── מה שיורד

    [Theory]
    [InlineData("http://example.com/x.exe")]
    [InlineData("ftp://example.com/x.exe")]
    [InlineData("file:///C:/x.exe")]
    [InlineData("not-a-url")]
    public void A_non_https_url_is_refused(string url)
    {
        var verdict = Judge(Offer(o => o.DownloadUrl = url));

        Assert.Equal(UpdateRejection.BadUrl, verdict.Reason);
    }

    [Theory]
    [InlineData("")]
    [InlineData("abc")]
    [InlineData("zz4cb572b423663bfe9f3c34acc1d5191a535c57393765c0e7bb138d8c3b6d51")]
    public void A_malformed_digest_is_refused(string digest)
    {
        // גיבוב בצורה שגויה לא יתאים לעולם, וההורדה כולה תהיה
        // בזבוז של 60 מגה.
        var verdict = Judge(Offer(o => o.Sha256 = digest));

        Assert.Equal(UpdateRejection.BadDigest, verdict.Reason);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void A_nonsensical_size_is_refused(long size)
    {
        var verdict = Judge(Offer(o => o.SizeBytes = size));

        Assert.Equal(UpdateRejection.TooLarge, verdict.Reason);
    }

    [Fact]
    public void A_size_beyond_the_ceiling_is_refused()
    {
        var verdict = Judge(Offer(o => o.SizeBytes = UpdateGate.MaxBytes + 1));

        Assert.Equal(UpdateRejection.TooLarge, verdict.Reason);
    }

    // ─────────────────────────────────────────────── סדר הבדיקות

    [Fact]
    public void The_device_is_checked_before_anything_else()
    {
        /*
         * הצעה פגומה בכל דרך אפשרית, שנועדה למחשב אחר.
         *
         * הסדר חשוב: הבדיקה הזולה והמסוכנת ביותר קודמת, כדי
         * שהודעת הדחייה תצביע על הבעיה האמיתית ולא על תסמין.
         */
        var verdict = Judge(Offer(o =>
        {
            o.HwidHash = new string('0', 64);
            o.Version = "לא גרסה";
            o.DownloadUrl = "http://x";
            o.Sha256 = "";
        }));

        Assert.Equal(UpdateRejection.WrongDevice, verdict.Reason);
    }
}
