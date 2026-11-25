using FilterPlus.Core.Models;

namespace FilterPlus.Tests;

public sealed class TrayPromotionTests
{
    [Fact]
    public void NoDecisionYetMeansPromote()
    {
        // Windows מסתירה אייקון חדש. זו ברירת מחדל שלה, לא בחירה
        // של ההורה — ולכן מותר לשנות אותה.
        Assert.Equal(PromotionAction.Promote, TrayPromotion.Decide(isPromoted: null, alreadyTried: false));
    }

    [Fact]
    public void HiddenOnPurposeStaysHidden()
    {
        /*
         * IsPromoted=0 פירושו שמישהו הכריע. כפייה כאן הייתה הופכת
         * הגדרה של המשתמש להצעה, ומאלצת אותו להילחם בתוכנה בכל
         * הפעלה מחדש.
         */
        Assert.Equal(PromotionAction.Leave, TrayPromotion.Decide(isPromoted: false, alreadyTried: false));
    }

    [Fact]
    public void AlreadyVisibleNeedsNothing()
    {
        Assert.Equal(PromotionAction.Leave, TrayPromotion.Decide(isPromoted: true, alreadyTried: false));
    }

    [Fact]
    public void OnceIsOnce()
    {
        /*
         * המקרה שבשבילו הזיכרון קיים: העלינו, ההורה הסתיר, והערך
         * חזר להיות null בגרסת Windows שמוחקת אותו. בלי הסימן
         * היינו מעלים שוב, וכך בכל הפעלה.
         */
        Assert.Equal(PromotionAction.Leave, TrayPromotion.Decide(isPromoted: null, alreadyTried: true));
        Assert.Equal(PromotionAction.Leave, TrayPromotion.Decide(isPromoted: false, alreadyTried: true));
    }
}
