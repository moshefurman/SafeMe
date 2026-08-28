using SafeMe.Core.Policy;
using SafeMe.Service.Audit;
using Xunit;

namespace SafeMe.Tests;

/// <summary>
/// התאמת מנפיק התעודה.
///
/// הערכים כאן נמדדו על מכונה מסוננת אמיתית, ולא נלקחו ממסמך: רימון
/// מסננת דרך NetSpark, ועל מארח שהיא מגישה עליו דף חסימה היא מציגה
/// תעודה עם E=support@netspark.com. בגלישה רגילה היא שקופה לגמרי
/// והתעודות הן האמיתיות.
/// </summary>
public class TlsIssuerMatchTests
{
    private const string NetSpark =
        "E=support@netspark.com, CN=NetSpark, OU=NetSpark, O=NetSpark, L=Jerusalem, C=IL";

    [Theory]
    [InlineData("*netspark*")]
    [InlineData("*NetSpark*")]
    [InlineData("*support@netspark.com*")]
    public void The_measured_netspark_issuer_matches(string pattern)
        => Assert.True(Wildcard.IsMatch(NetSpark, pattern));

    /// <summary>
    /// והמנפיקים האמיתיים אינם תואמים.
    ///
    /// זו הבדיקה שקובעת: תבנית רחבה מדי הייתה מזהה כל אתר כמסונן,
    /// והמוצר היה מדווח "מוגן" על מחשב פתוח לגמרי.
    /// </summary>
    [Theory]
    [InlineData("CN=YE2, O=Let's Encrypt, C=US")]
    [InlineData("CN=WR2, O=Google Trust Services, C=US")]
    [InlineData("CN=GlobalSign GCC R46 OV TLS CA 2025, O=GlobalSign nv-sa, C=BE")]
    [InlineData("CN=Sectigo Public Server Authentication CA DV E36, O=Sectigo Limited, C=GB")]
    public void Real_issuers_do_not_match(string issuer)
    {
        Assert.False(Wildcard.IsMatch(issuer, "*netspark*"));
        Assert.False(Wildcard.IsMatch(issuer, "*rimon*"));
    }

    /// <summary>
    /// נטפרי מזוהה גם היא לפי מנפיק, על מכונה שבה היא הפרוקסי.
    /// </summary>
    [Fact]
    public void The_netfree_issuer_matches_its_pattern()
    {
        const string issuer =
            "CN=NetFree Root CA 1990-2200 RSA, OU=netfree.link, O=NetFree, S=Modi'in Ilit, C=IL";

        Assert.True(Wildcard.IsMatch(issuer, "*O=NetFree*"));
        Assert.False(Wildcard.IsMatch(issuer, "*netspark*"));
    }
}
