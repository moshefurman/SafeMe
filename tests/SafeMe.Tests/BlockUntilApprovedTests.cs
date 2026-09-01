using System.Text.Json;

using SafeMe.Core;
using SafeMe.Core.Policy;

namespace SafeMe.Tests;

/// <summary>
/// רשת שטרם הוכרעה: לחסום או לאשר.
///
/// כשהרשת מתחלפת הסוכן מוחק את ההכרעה הקודמת — היא נאמרה על רשת
/// אחרת — ואז עליו להחליט מה לעשות עד שתגיע הכרעה חדשה. שני
/// הכיוונים נכונים במצבים שונים, וכל אחד מהם נכשל בשטח בכיוון
/// השני:
///
///   שחרור  — לקוח שהגדיר "אף רשת עד אישור" התחבר לרשת חדשה וגלש.
///   חסימה  — מחשב נחסם על סמך הכרעה שאינה נוגעת לרשת שהוא מחובר
///            אליה, בלי מוצא.
///
/// לכן ההכרעה נשענת על המדיניות, ולא על ברירת מחדל קבועה.
/// </summary>
public class BlockUntilApprovedTests
{
    [Fact]
    public void Default_policy_does_not_hold_new_networks()
    {
        /*
         * ברירת המחדל אינה חוסמת, ובכוונה.
         *
         * מדיניות קיימת בשדה אינה כוללת את השדה הזה כלל, ושדה חסר
         * שהיה נקרא כ"חסום" היה משנה התנהגות של כל מחשב מותקן ברגע
         * שהשרת מתעדכן — בלי שאיש ביקש.
         */
        Assert.False(new AllowedNetworks().BlockUntilApproved);
        Assert.False(PolicyBundle.CreateDefault().Enforcement.AllowedNetworks.BlockUntilApproved);
    }

    [Fact]
    public void Missing_field_stays_permissive()
    {
        // בדיוק הצורה שמדיניות ישנה מגיעה בה: allowedNetworks בלי השדה
        const string body = """
            {
              "version": 22,
              "enforcement": {
                "mode": "enforce",
                "allowedNetworks": { "wifiSsids": ["בית"], "cidrs": [] }
              }
            }
            """;

        var policy = JsonSerializer.Deserialize<PolicyBundle>(body, SafeMeJson.Options);

        Assert.NotNull(policy);
        Assert.False(policy!.Enforcement.AllowedNetworks.BlockUntilApproved);
        Assert.Equal(["בית"], policy.Enforcement.AllowedNetworks.WifiSsids);
    }

    [Fact]
    public void Server_flag_reaches_the_agent()
    {
        /*
         * הצורה שהשרת שולח, מילה במילה מ-recompose.ts.
         *
         * זה הגשר כולו: השדה נכתב שם בשם הזה, ואם הסוכן לא יקרא
         * אותו הוא פשוט ימשיך לאשר — בלי שגיאה, ובלי שאיש ידע.
         */
        const string body = """
            {
              "version": 23,
              "enforcement": {
                "allowedNetworks": { "wifiSsids": [], "cidrs": [], "blockUntilApproved": true }
              }
            }
            """;

        var policy = JsonSerializer.Deserialize<PolicyBundle>(body, SafeMeJson.Options);

        Assert.True(policy!.Enforcement.AllowedNetworks.BlockUntilApproved);
    }

    [Fact]
    public void Round_trip_keeps_the_flag()
    {
        // המדיניות נשמרת לדיסק מסודרת מחדש מהאובייקט. שדה שאובד
        // בשמירה חוזר לברירת המחדל אחרי כל הפעלה של השירות.
        var policy = PolicyBundle.CreateDefault();

        policy.Enforcement.AllowedNetworks.BlockUntilApproved = true;

        var again = JsonSerializer.Deserialize<PolicyBundle>(
            JsonSerializer.Serialize(policy, SafeMeJson.Options), SafeMeJson.Options);

        Assert.True(again!.Enforcement.AllowedNetworks.BlockUntilApproved);
    }
}
