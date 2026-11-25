using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using FilterPlus.Core;
using FilterPlus.Core.Ipc;

namespace FilterPlus.Service.Ipc;

/// <summary>
/// שרת ה-IPC. מאזין ב-Named Pipe ומטפל בבקשות מ-TrayApp וממסך ההסרה.
///
/// אבטחה:
///   * ה-ACL מאפשר למשתמשים רגילים רק לפתוח את הצינור ולשלוח בקשות סטטוס.
///   * פעולות רגישות נבדקות מול הרמת ההרשאות של תהליך הלקוח.
///   * גודל הודעה מוגבל כדי למנוע מיצוי זיכרון.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class IpcServer : BackgroundService
{
    /// <summary>כמה מופעי צינור מקבילים לאפשר. מספיק לכמה סשנים בו-זמנית.</summary>
    private const int MaxInstances = 8;

    private readonly ILogger<IpcServer> _log;
    private readonly IpcRequestHandler _handler;

    public IpcServer(ILogger<IpcServer> log, IpcRequestHandler handler)
    {
        _log = log;
        _handler = handler;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _log.LogInformation("שרת IPC מאזין בצינור {Pipe}.", IpcConstants.PipeName);

        var workers = new List<Task>();

        for (var i = 0; i < MaxInstances; i++)
            workers.Add(RunListenerAsync(stoppingToken));

        await Task.WhenAll(workers);
    }

    private async Task RunListenerAsync(CancellationToken ct)
    {
        var accessDeniedReported = false;

        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;

            try
            {
                pipe = CreatePipe();

                await pipe.WaitForConnectionAsync(ct);
                await HandleConnectionAsync(pipe, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (UnauthorizedAccessException ex)
            {
                // יצירת מופע נוסף של צינור קיים דורשת FILE_CREATE_PIPE_INSTANCE,
                // שקיים ל-SYSTEM ולמנהלים בלבד. בהרצה ללא הרמה מופע אחד יעבוד
                // והשאר יידחו, ולכן מדווחים פעם אחת ולא בכל סיבוב.
                if (!accessDeniedReported)
                {
                    accessDeniedReported = true;

                    _log.LogWarning(ex,
                        "לא ניתן ליצור מופע צינור נוסף. בהרצה שאינה כ-SYSTEM זו התנהגות צפויה, " +
                        "והשירות ימשיך לעבוד עם פחות חיבורים מקבילים.");
                }

                if (!await SafeDelay(TimeSpan.FromSeconds(30), ct)) break;
            }
            catch (IOException ex)
            {
                // ניתוק לקוח באמצע הוא מצב רגיל לחלוטין
                _log.LogDebug(ex, "חיבור IPC נותק.");
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "שגיאה בטיפול בחיבור IPC.");

                // מניעת לולאת שגיאות צמודה שתשרוף מעבד
                if (!await SafeDelay(TimeSpan.FromSeconds(1), ct)) break;
            }
            finally
            {
                if (pipe is not null)
                {
                    if (pipe.IsConnected)
                    {
                        try { pipe.Disconnect(); } catch (Exception) { /* כבר נותק */ }
                    }

                    await pipe.DisposeAsync();
                }
            }
        }
    }

    /// <summary>המתנה שאינה זורקת בכיבוי. מחזירה false אם התבקש כיבוי.</summary>
    private static async Task<bool> SafeDelay(TimeSpan delay, CancellationToken ct)
    {
        try
        {
            await Task.Delay(delay, ct);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    /// <summary>יוצר מופע צינור עם ACL מוקשח.</summary>
    private static NamedPipeServerStream CreatePipe()
    {
        var security = new PipeSecurity();

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);

        security.AddAccessRule(new PipeAccessRule(system, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(admins, PipeAccessRights.FullControl, AccessControlType.Allow));

        // משתמשים רגילים יכולים לשלוח בקשות ולקרוא תשובות, אך לא לשנות את הצינור
        security.AddAccessRule(new PipeAccessRule(
            users,
            PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize,
            AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(
            IpcConstants.PipeName,
            PipeDirection.InOut,
            MaxInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.WriteThrough,
            inBufferSize: 16 * 1024,
            outBufferSize: 64 * 1024,
            security);
    }

    private async Task HandleConnectionAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        using var reader = new StreamReader(pipe, Encoding.UTF8, false, 16 * 1024, leaveOpen: true);

        var line = await reader.ReadLineAsync(ct);

        if (string.IsNullOrWhiteSpace(line)) return;

        if (line.Length > IpcConstants.MaxMessageBytes)
        {
            _log.LogWarning("הודעת IPC חורגת מהגודל המותר ונדחתה.");
            return;
        }

        IpcResponse response;

        if (!FilterPlusJson.TryDeserialize<IpcRequest>(line, out var request) || request is null)
        {
            response = IpcResponse.Failure(Guid.Empty, "בקשה לא תקינה.");
        }
        else if (IpcOps.RequiresElevation.Contains(request.Op) && !ClientElevation.IsClientElevated(pipe))
        {
            _log.LogWarning("בקשה {Op} נדחתה: הלקוח אינו מורם.", request.Op);
            response = IpcResponse.Failure(request.Id, "הפעולה דורשת הרשאות מנהל.");
        }
        else
        {
            response = await _handler.HandleAsync(request, ct);
        }

        var payload = FilterPlusJson.Serialize(response) + "\n";

        await pipe.WriteAsync(Encoding.UTF8.GetBytes(payload), ct);
        await pipe.FlushAsync(ct);

        // המתנה לקריאת הלקוח לפני ניתוק, כדי שהתשובה לא תיקטע
        try { pipe.WaitForPipeDrain(); } catch (Exception) { /* הלקוח כבר עזב */ }
    }
}

/// <summary>מפענח את גוף הבקשה לטיפוס המבוקש.</summary>
public static class IpcPayloadExtensions
{
    public static T? Read<T>(this IpcRequest request)
    {
        if (request.Payload is not { } element) return default;
        if (element.ValueKind == JsonValueKind.Null) return default;

        return element.Deserialize<T>(FilterPlusJson.Options);
    }
}
