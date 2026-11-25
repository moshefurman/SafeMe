using FilterPlus.Core.Ipc;
using FilterPlus.Core.Models;
using FilterPlus.Core.Policy;

namespace FilterPlus.TrayApp.Services;

/// <summary>
/// דוגם את סטטוס הסוכן דרך ה-IPC ומפרסם אותו לשאר הרכיבים.
///
/// כשהשירות אינו זמין מוצג סטטוס אפור עם הסבר, במקום להיעלם בשקט.
/// המשתמש תמיד צריך לדעת אם ההגנה פעילה או לא.
/// </summary>
public sealed class StatusPoller : IDisposable
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(5);

    private readonly IpcClient _client = new();
    private readonly CancellationTokenSource _cts = new();

    private Task? _loop;

    /// <summary>הסטטוס האחרון שהתקבל.</summary>
    public StatusSnapshot Current { get; private set; } = new()
    {
        Status = SecurityStatus.Unknown,
        Headline = "מתחבר לשירות FilterPlus..."
    };

    /// <summary>true אם השירות הגיב בדגימה האחרונה.</summary>
    public bool ServiceReachable { get; private set; }

    public event Action<StatusSnapshot>? StatusChanged;

    public void Start() => _loop ??= Task.Run(() => PollLoopAsync(_cts.Token));

    /// <summary>מבקש מהשירות ביקורת מיידית ומחזיר את הדוח.</summary>
    public async Task<AuditReport?> RequestAuditAsync()
    {
        try
        {
            return await _client.SendAsync<AuditReport>(IpcOps.RunAuditNow, null, _cts.Token);
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// מבקש מהשירות פעימה מיידית מול השרת, כדי לקלוט אישור רשת או
    /// שינוי מדיניות בלי להמתין למחזור הבא. מחזיר true אם הבקשה
    /// התקבלה. הקליטה עצמה מתעדכנת בדגימה הבאה.
    /// </summary>
    public async Task<bool> RequestRefreshAsync()
    {
        try
        {
            var response = await _client.SendAsync(IpcOps.RefreshNow, null, _cts.Token);
            return response.Ok;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private async Task PollLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            await PollOnceAsync(ct);

            try
            {
                await Task.Delay(PollInterval, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    public async Task PollOnceAsync(CancellationToken ct)
    {
        try
        {
            var snapshot = await _client.SendAsync<StatusSnapshot>(IpcOps.GetStatus, null, ct);

            if (snapshot is null) return;

            ServiceReachable = true;
            Current = snapshot;

            StatusChanged?.Invoke(snapshot);
        }
        catch (OperationCanceledException)
        {
            // כיבוי
        }
        catch (Exception)
        {
            ServiceReachable = false;

            Current = new StatusSnapshot
            {
                Status = SecurityStatus.Unknown,
                Headline = "שירות FilterPlus אינו פעיל. ההגנה אינה בתוקף."
            };

            StatusChanged?.Invoke(Current);
        }
    }

    public void Dispose()
    {
        _cts.Cancel();

        try
        {
            _loop?.Wait(TimeSpan.FromSeconds(2));
        }
        catch (Exception)
        {
            // סגירה בכל מקרה
        }

        _cts.Dispose();
    }
}
