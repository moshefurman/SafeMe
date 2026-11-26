using FilterPlus.Service.Integrity;

using Xunit;

namespace FilterPlus.Tests;

/// <summary>
/// מה נחשב "מוקשח". הבדיקה הזו היא שמחליטה אם הסוכן מדווח על חבלה,
/// ולכן כל מתאר שמתיר למנהל לעצור או לשנות הרשאות חייב להיכשל בה.
/// </summary>
public class ServiceHardeningTests
{
    private const string Sys = "(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;SY)";
    private const string Tail = "(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";

    [Fact]
    public void TheInstalledDescriptorIsHardened()
    {
        Assert.True(ServiceHardening.IsHardenedDescriptor(
            $"D:{Sys}(A;;CCLCSWRPLOCRRC;;;BA){Tail}"));
    }

    [Fact]
    public void WhitespaceFromScOutputIsIgnored()
    {
        Assert.True(ServiceHardening.IsHardenedDescriptor(
            $"\r\nD:{Sys}(A;;CCLCSWRPLOCRRC;;;BA){Tail}\r\n\r\n"));
    }

    [Fact]
    public void TheDescriptorFromBefore1_1_61IsNoLongerHardened()
    {
        // WD למנהלים: sc sdset אחד מחזיר להם את זכות העצירה.
        Assert.False(ServiceHardening.IsHardenedDescriptor(
            $"D:{Sys}(A;;CCLCSWRPLOCRRCWD;;;BA){Tail}"));
    }

    [Fact]
    public void TheDefaultDescriptorIsNotHardened()
    {
        Assert.False(ServiceHardening.IsHardenedDescriptor(
            $"D:{Sys}(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;BA){Tail}"));
    }

    [Fact]
    public void AnExtraAdminEntryBesideTheOriginalIsNotHardened()
    {
        // הרשומה המקורית נשארה במקומה, ולצידה נוספה אחת שמתירה עצירה.
        Assert.False(ServiceHardening.IsHardenedDescriptor(
            $"D:{Sys}(A;;CCLCSWRPLOCRRC;;;BA)(A;;WP;;;BA){Tail}"));
    }

    [Fact]
    public void ADescriptorWithoutAdminsIsNotHardened()
    {
        Assert.False(ServiceHardening.IsHardenedDescriptor($"D:{Sys}{Tail}"));
    }
}
