using SafeMe.Core.Audit;

namespace SafeMe.Tests;

public sealed class NetworkIdentityTrackerTests
{
    [Fact]
    public void FirstObservationIsNotAChange()
    {
        var tracker = new NetworkIdentityTracker();

        // אין ממה להתחלף. הביקורת ממילא רצה עשר שניות אחרי עליית השירות.
        Assert.False(tracker.Changed("Rimon|192.168.1.1"));
    }

    [Fact]
    public void SameNetworkRepeatedIsNotAChange()
    {
        var tracker = new NetworkIdentityTracker();
        tracker.Changed("Rimon|192.168.1.1");

        // הפעימה רצה כל שלוש דקות. אם כל אחת מהן תריץ ביקורת,
        // המנגנון של רבע השעה מפסיק להתקיים.
        Assert.False(tracker.Changed("Rimon|192.168.1.1"));
        Assert.False(tracker.Changed("Rimon|192.168.1.1"));
    }

    [Fact]
    public void MovingToAnotherNetworkIsAChange()
    {
        var tracker = new NetworkIdentityTracker();
        tracker.Changed("Rimon|192.168.1.1");

        Assert.True(tracker.Changed("4GMIFI_4898|192.168.0.1"));
    }

    [Fact]
    public void SameNameDifferentGatewayIsAChange()
    {
        var tracker = new NetworkIdentityTracker();
        tracker.Changed("HOME|192.168.1.1");

        // שם הרשת לבדו אינו זהות. "HOME" בבית ו-"HOME" אצל השכן
        // הן שתי רשתות, ורק אחת מהן עשויה להיות מסוננת.
        Assert.True(tracker.Changed("HOME|10.0.0.1"));
    }

    [Fact]
    public void CaseDoesNotMakeItANewNetwork()
    {
        var tracker = new NetworkIdentityTracker();
        tracker.Changed("Rimon|192.168.1.1");

        Assert.False(tracker.Changed("RIMON|192.168.1.1"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void UnknownIdentityIsNeverAChange(string? identity)
    {
        var tracker = new NetworkIdentityTracker();
        tracker.Changed("Rimon|192.168.1.1");

        // מתאם שירד לרגע מחזיר ריק. ביקורת שתרוץ אז תמדוד רשת
        // שאינה קיימת, ותדווח "לא מסונן" על סמך כלום.
        Assert.False(tracker.Changed(identity));
    }

    [Fact]
    public void UnknownIdentityDoesNotEraseTheBaseline()
    {
        var tracker = new NetworkIdentityTracker();
        tracker.Changed("Rimon|192.168.1.1");
        tracker.Changed(null);

        // אחרי הפסקה קצרה, חזרה לאותה רשת אינה החלפה — ומעבר
        // לרשת אחרת עדיין כן. אילו הריק היה מאפס את קו הבסיס,
        // ההחלפה האמיתית הייתה נבלעת.
        Assert.False(tracker.Changed("Rimon|192.168.1.1"));

        tracker.Changed(null);
        Assert.True(tracker.Changed("4GMIFI_4898|192.168.0.1"));
    }

    [Fact]
    public void ReturningToAPreviousNetworkIsAChange()
    {
        var tracker = new NetworkIdentityTracker();
        tracker.Changed("Rimon|192.168.1.1");
        tracker.Changed("4GMIFI_4898|192.168.0.1");

        // חזרה לרימון היא בדיוק המקרה שבו הביקורת חייבת לרוץ:
        // המחשב הפך למסונן, והמצב המוצג אומר שאינו.
        Assert.True(tracker.Changed("Rimon|192.168.1.1"));
    }
}
