using FilterPlus.Core.Models;

namespace FilterPlus.Tests;

public sealed class IspIdentityTests
{
    /// <summary>התשובה שנמדדה בפועל מרשת ללא סינון.</summary>
    private const string Measured = """
        {
          "ip": "147.234.101.242",
          "city": "Tel Aviv",
          "region": "Tel Aviv",
          "country": "IL",
          "loc": "32.0809,34.7806",
          "org": "AS51825 Telzar 019 International Telecommunications Services LTD",
          "timezone": "Asia/Jerusalem",
          "readme": "https://ipinfo.io/missingauth"
        }
        """;

    [Fact]
    public void ReadsTheMeasuredResponse()
    {
        var isp = IspIdentity.Read(Measured);

        Assert.Equal(51825, isp.Asn);
        Assert.Equal("Telzar 019 International Telecommunications Services LTD", isp.Name);
        Assert.Equal("AS51825", isp.Key);
        Assert.True(isp.IsKnown);
    }

    [Fact]
    public void KeyIsTheNumberAndNotTheName()
    {
        var renamed = IspIdentity.Parse("AS51825 Telzar 019 Ltd.");
        var original = IspIdentity.Parse("AS51825 Telzar 019 International Telecommunications Services LTD");

        // מיתוג מחדש אינו החלפת ספק, ואסור שיבקש אישור מחדש
        Assert.Equal(original.Key, renamed.Key);
    }

    [Fact]
    public void DifferentAsnIsADifferentProvider()
    {
        var wired = IspIdentity.Parse("AS51825 Telzar 019");
        var cellular = IspIdentity.Parse("AS12400 Partner Communications");

        Assert.NotEqual(wired.Key, cellular.Key);
    }

    [Fact]
    public void NameWithoutNumberStillIdentifies()
    {
        var isp = IspIdentity.Parse("Some Provider Ltd");

        Assert.Null(isp.Asn);
        Assert.Equal("Some Provider Ltd", isp.Name);
        Assert.Equal("Some Provider Ltd", isp.Key);
        Assert.True(isp.IsKnown);
    }

    [Fact]
    public void NumberWithoutNameStillIdentifies()
    {
        var isp = IspIdentity.Parse("AS51825");

        Assert.Equal(51825, isp.Asn);
        Assert.Null(isp.Name);
        Assert.Equal("AS51825", isp.Key);
    }

    [Fact]
    public void AsInsideTheNameIsNotAPrefix()
    {
        // "ASIA" מתחיל ב-AS ואינו מספר. פירוק תמים היה מייצר ספק
        // חדש בכל פעם שהשם משתנה קלות.
        var isp = IspIdentity.Parse("ASIA Networks Ltd");

        Assert.Null(isp.Asn);
        Assert.Equal("ASIA Networks Ltd", isp.Name);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not json at all")]
    [InlineData("{}")]
    [InlineData("""{"org": 5}""")]
    [InlineData("""{"ip":"1.2.3.4"}""")]
    public void UnreadableAnswerIsUnknownAndNotAProvider(string? json)
    {
        var isp = IspIdentity.Read(json);

        /*
         * זו הנקודה הרגישה כאן.
         *
         * הבדיקה מגיעה מהרשת, והיא נכשלת בדיוק כשהרשת חסומה —
         * כלומר ברגע שבו המשפחה הכי זקוקה לכך שהמחשב לא יינעל
         * מסיבה שאינה קשורה. "לא ידוע" חייב להיות היעדר ידיעה,
         * ולעולם לא ספק חדש שדורש אישור.
         */
        Assert.False(isp.IsKnown);
        Assert.Null(isp.Key);
    }

    [Fact]
    public void UnknownIsNotEqualToAnyProvider()
    {
        Assert.NotEqual(IspIdentity.Unknown.Key, IspIdentity.Parse("AS51825 Telzar").Key);
        Assert.Null(IspIdentity.Unknown.Key);
    }
}
