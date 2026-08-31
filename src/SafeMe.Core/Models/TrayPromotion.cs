namespace SafeMe.Core.Models;

/// <summary>מה לעשות עם רשומת האייקון של Windows.</summary>
public enum PromotionAction
{
    /// <summary>לא לגעת. אין רשומה, או שכבר יש החלטה.</summary>
    Leave,

    /// <summary>להעלות לשורת המשימות. פעם אחת, ורק כשאיש לא הכריע.</summary>
    Promote
}

/// <summary>
/// האם להעלות את אייקון המגש לשורת המשימות.
///
/// Windows מסתירה אייקון של אפליקציה חדשה מאחורי החץ, וזו התנהגות
/// סבירה לרוב התוכנות. כאן היא מזיקה: האייקון הוא הדבר היחיד שההורה
/// רואה שאומר שההגנה פועלת. כשהוא אינו שם, המסקנה הסבירה היא
/// שהתוכנה הוסרה.
///
/// זה נצפה מיד אחרי התקנה — "איך האייקון נעלם פתאום מהמסך?" — והמצב
/// היה תקין לגמרי: התהליך רץ, ההגנה פעלה, והאייקון ישב מוסתר.
///
/// ההעלאה נעשית פעם אחת בלבד, ורק כשלמשתמש אין החלטה קודמת.
/// הורה שבחר להסתיר את האייקון בחר, וכפייה בכל הפעלה הייתה הופכת
/// הגדרה של המשתמש להצעה.
/// </summary>
public static class TrayPromotion
{
    /// <summary>
    /// <paramref name="isPromoted"/> הוא הערך שנקרא מהרשומה:
    /// null כשהשדה אינו קיים, כלומר איש לא הכריע.
    ///
    /// <paramref name="alreadyTried"/> הוא מה שאנחנו זוכרים על עצמנו.
    /// בלעדיו היינו מעלים שוב אחרי שההורה הסתיר, בכל הפעלה מחדש —
    /// והוא היה נלחם בתוכנה על ההגדרה שלו.
    /// </summary>
    public static PromotionAction Decide(bool? isPromoted, bool alreadyTried)
    {
        if (alreadyTried) return PromotionAction.Leave;

        // מוסתר במפורש. זו החלטה, ומכבדים אותה.
        if (isPromoted is not null) return PromotionAction.Leave;

        return PromotionAction.Promote;
    }
}
