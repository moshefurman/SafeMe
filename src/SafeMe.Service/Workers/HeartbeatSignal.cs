namespace SafeMe.Service.Workers;

/// <summary>
/// גשר בין בקשת רענון (מ-IPC) לבין לולאת הפעימה.
///
/// לולאת הפעימה ישנה בין מחזורים. כשמגיעה בקשת רענון היא משחררת
/// את השינה מיד, כך שהפעימה הבאה יוצאת עכשיו ולא בעוד שלוש דקות.
/// זהו הערוץ היחיד — לסוכן אין דחיפה מהשרת, ולכן "מיד" פירושו
/// לעורר את המחזור המקומי, וזה בתורו מושך מהשרת.
///
/// קיבולת אחת בכוונה: כמה לחיצות בזו אחר זו מתלכדות לפעימה אחת,
/// ולא מייצרות תור של פעימות מיותרות.
/// </summary>
public sealed class HeartbeatSignal
{
    private readonly SemaphoreSlim _pending = new(0, 1);

    /// <summary>מבקש פעימה מיידית. בטוח לקריאה חוזרת.</summary>
    public void RequestNow()
    {
        try
        {
            _pending.Release();
        }
        catch (SemaphoreFullException)
        {
            // כבר יש בקשה ממתינה. אין צורך בשנייה.
        }
    }

    /// <summary>
    /// ממתין עד לבקשת רענון או עד שהזמן חלף.
    /// מחזיר true אם התעוררנו בגלל בקשה, false אם בגלל הזמן.
    /// בכל מקרה הקורא ימשיך לפעימה — ההבחנה נועדה ליומן בלבד.
    /// </summary>
    public Task<bool> WaitAsync(TimeSpan timeout, CancellationToken ct) =>
        _pending.WaitAsync(timeout, ct);
}
