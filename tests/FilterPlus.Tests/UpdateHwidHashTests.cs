using System.Text.Json;

using FilterPlus.Core.Security;
using FilterPlus.Core.Models;
using FilterPlus.Core.Updates;

namespace FilterPlus.Tests;

/// <summary>
/// גיבוב מזהה החומרה בהצעת עדכון.
///
/// נכתב אחרי שהתברר שהסוכן והשרת חישבו אותו דבר בשתי דרכים שונות:
/// השרת נרמל לאותיות גדולות ולקח שמונה בתים, הסוכן לא נרמל ולקח
/// שלושים ושניים. כל הצעת עדכון נדחתה כ"נועדה למחשב אחר".
///
/// מה שהופך את זה למסוכן במיוחד: המנגנון נראה עובד לגמרי. הוא רץ,
/// קיבל הצעה, אימת חתימה, ודחה בסיבה שנשמעת הגיונית — כלומר בדיוק
/// כמו הגנה שעושה את עבודתה. הוא פשוט מעולם לא עדכן דבר.
/// </summary>
public sealed class UpdateHwidHashTests
{
    private static string ServerFormat(string hwid) =>
        Convert.ToHexString(UninstallChallenge.ComputeHwidHash(hwid));

    /// <summary>
    /// הפורמט מקובע מול הווקטור המשותף, שהצד ב-TypeScript נבדק
    /// מולו גם הוא. זה מה שמונע מהשניים להיפרד שוב.
    /// </summary>
    [Fact]
    public void MatchesTheSharedVector()
    {
        var json = JsonDocument.Parse(File.ReadAllText(VectorPath()));
        var offer = json.RootElement.GetProperty("updateOffer");

        var hwid = offer.GetProperty("hwid").GetString()!;
        var expected = offer.GetProperty("hwidHash").GetString()!;

        Assert.Equal(expected, ServerFormat(hwid));
    }

    /// <summary>שמונה בתים, לא שלושים ושניים. זה היה ההבדל.</summary>
    [Fact]
    public void IsSixteenHexCharacters()
    {
        Assert.Equal(16, ServerFormat("ANY-MACHINE-ID").Length);
    }

    /// <summary>הקלט מנורמל, ולכן אותיות אינן משנות את התוצאה.</summary>
    [Fact]
    public void NormalisesCaseAndWhitespace()
    {
        var expected = ServerFormat("ABC-123");

        Assert.Equal(expected, ServerFormat("abc-123"));
        Assert.Equal(expected, ServerFormat("  ABC-123  "));
    }

    /// <summary>
    /// המסלול השלם: הצעה שנושאת את הגיבוב בפורמט השרת מתקבלת.
    ///
    /// זו הבדיקה שהייתה נכשלת לפני התיקון, ולכן היא הבדיקה שחשובה.
    /// </summary>
    [Fact]
    public void OfferForThisMachineIsAccepted()
    {
        const string hwid = "TESTHWID0123456789ABCDEF";

        var now = DateTimeOffset.UtcNow;

        var offer = new UpdateOffer
        {
            Version = "1.1.9",
            DownloadUrl = "https://example.com/FilterPlus-Setup.exe",
            Sha256 = new string('a', 64),
            SizeBytes = 64_501_459,
            HwidHash = ServerFormat(hwid),
            IssuedUtc = now,
            ExpiresUtc = now.AddMinutes(30),
        };

        var verdict = UpdateGate.Evaluate(offer, "1.1.4", ServerFormat(hwid), now);

        Assert.True(verdict.Accepted, verdict.Explanation);
    }

    [Fact]
    public void OfferForAnotherMachineIsRejected()
    {
        var now = DateTimeOffset.UtcNow;

        var offer = new UpdateOffer
        {
            Version = "1.1.9",
            DownloadUrl = "https://example.com/FilterPlus-Setup.exe",
            Sha256 = new string('a', 64),
            SizeBytes = 1000,
            HwidHash = ServerFormat("SOMEONE-ELSE"),
            IssuedUtc = now,
            ExpiresUtc = now.AddMinutes(30),
        };

        var verdict = UpdateGate.Evaluate(offer, "1.1.4", ServerFormat("THIS-MACHINE"), now);

        Assert.False(verdict.Accepted);
        Assert.Equal(UpdateRejection.WrongDevice, verdict.Reason);
    }

    private static string VectorPath()
    {
        var dir = AppContext.BaseDirectory;

        for (var i = 0; i < 8 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir, "shared", "test-vectors.json");

            if (File.Exists(candidate)) return candidate;

            dir = Path.GetDirectoryName(dir);
        }

        throw new FileNotFoundException("לא נמצא shared/test-vectors.json");
    }
}
