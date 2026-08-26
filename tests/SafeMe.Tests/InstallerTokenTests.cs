using SafeMe.Core.Security;
using Xunit;

namespace SafeMe.Tests;

/// <summary>
/// חילוץ אסימון ההתקנה משם הקובץ.
///
/// זהו הצעד הראשון בכל התקנה, ולכן כל כשל כאן הוא כשל של המוצר
/// מהרגע הראשון. הבדיקות מתמקדות במה שדפדפנים ומערכות הפעלה עושים
/// לשמות קבצים בפועל, ולא במה שהם אמורים לעשות.
/// </summary>
public class InstallerTokenTests
{
    private const string Body = "A1B2C3D4E5F60718293A4B5C";
    private const string Token = "ENR-" + Body;

    [Fact]
    public void שם_רגיל()
    {
        Assert.Equal(Token, InstallerToken.FromFileName($"SafeMe-Setup-{Token}.exe"));
    }

    [Fact]
    public void נתיב_מלא()
    {
        Assert.Equal(
            Token,
            InstallerToken.FromFileName($@"C:\Users\Moshe\Downloads\SafeMe-Setup-{Token}.exe"));
    }

    /// <summary>
    /// הורדה חוזרת באותו דפדפן מוסיפה סיומת כפילות. זה קורה בפועל
    /// לכל מי שמוריד פעמיים, ולכן זה לא מקרה קצה.
    /// </summary>
    [Theory]
    [InlineData("SafeMe-Setup-{0} (1).exe")]
    [InlineData("SafeMe-Setup-{0} (12).exe")]
    [InlineData("SafeMe-Setup-{0}(1).exe")]
    [InlineData("SafeMe-Setup-{0}[1].exe")]
    [InlineData("SafeMe-Setup-{0}-2.exe")]
    [InlineData("  SafeMe-Setup-{0}.exe  ")]
    public void סיומות_שדפדפנים_מוסיפים(string template)
    {
        var name = string.Format(template, Token);

        Assert.Equal(Token, InstallerToken.FromFileName(name));
    }

    /// <summary>
    /// מערכות קבצים ודפדפנים משנים רישיות. השרת מגבב אחרי המרה
    /// לאותיות גדולות, ולכן החילוץ חייב לנרמל.
    /// </summary>
    [Fact]
    public void רישיות_מנורמלת()
    {
        Assert.Equal(
            Token,
            InstallerToken.FromFileName($"safeme-setup-enr-{Body.ToLowerInvariant()}.exe"));
    }

    [Theory]
    [InlineData("SafeMe-Setup.exe")]
    [InlineData("installer.exe")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void בלי_אסימון(string? name)
    {
        Assert.Null(InstallerToken.FromFileName(name));
    }

    /// <summary>
    /// אסימון קצוץ או ארוך מדי נדחה. חיתוך שם קובץ קורה בהעברה
    /// דרך מערכות ישנות, ואסימון חלקי שיתקבל היה מפנה לחשבון אחר
    /// או נכשל ברישום בלי הסבר.
    /// </summary>
    [Theory]
    [InlineData("SafeMe-Setup-ENR-A1B2C3.exe")]
    [InlineData("SafeMe-Setup-ENR-A1B2C3D4E5F60718293A4B5C7D.exe")]
    [InlineData("SafeMe-Setup-ENR-.exe")]
    public void אורך_שגוי_נדחה(string name)
    {
        Assert.Null(InstallerToken.FromFileName(name));
    }

    /// <summary>
    /// תו שאינו הקסדצימלי בתוך הגוף פוסל. בלי זה, "ENR-" ואחריו
    /// עברית או סימנים היה עלול להתקבל חלקית.
    /// </summary>
    [Fact]
    public void תו_לא_הקסדצימלי_נדחה()
    {
        Assert.Null(InstallerToken.FromFileName("SafeMe-Setup-ENR-A1B2C3D4E5F60718293A4B5Z.exe"));
    }

    /// <summary>
    /// שני אסימונים בשם אחד: מצב לא צפוי שבו ניחוש גרוע מסירוב,
    /// כי הוא היה מחבר את המכשיר לחשבון שרירותי.
    /// </summary>
    [Fact]
    public void שני_אסימונים_נדחים()
    {
        var other = "ENR-FFFFFFFFFFFFFFFFFFFFFFFF";

        Assert.Null(InstallerToken.FromFileName($"SafeMe-{Token}-{other}.exe"));
    }

    [Fact]
    public void בניית_שם_וחילוץ_חוזר()
    {
        var name = InstallerToken.ToFileName(Token);

        Assert.Equal($"SafeMe-Setup-{Token}.exe", name);
        Assert.Equal(Token, InstallerToken.FromFileName(name));
    }

    [Fact]
    public void בניית_שם_מאסימון_פגום_נכשלת()
    {
        Assert.Throws<ArgumentException>(() => InstallerToken.ToFileName("ENR-123"));
        Assert.Throws<ArgumentException>(() => InstallerToken.ToFileName("שלום"));
    }

    [Fact]
    public void בדיקת_תקינות()
    {
        Assert.True(InstallerToken.IsWellFormed(Token));
        Assert.True(InstallerToken.IsWellFormed($"  {Token.ToLowerInvariant()}  "));

        Assert.False(InstallerToken.IsWellFormed("ENR-123"));
        Assert.False(InstallerToken.IsWellFormed($"x{Token}"));
        Assert.False(InstallerToken.IsWellFormed($"{Token}x"));
        Assert.False(InstallerToken.IsWellFormed(null));
    }
}
