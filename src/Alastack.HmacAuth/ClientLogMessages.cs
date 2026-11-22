using Microsoft.Extensions.Logging;

namespace Alastack.HmacAuth;

/// <summary>
/// Source-generated log messages for the Hmac and Hawk client handlers.
/// </summary>
internal static partial class ClientLogMessages
{
    [LoggerMessage(EventId = 1, Level = LogLevel.Debug, Message = "Hmac request signed. AppId={AppId} Method={Method} Uri={Uri} Timestamp={Timestamp}")]
    public static partial void HmacRequestSigned(ILogger logger, string appId, string method, Uri? uri, long timestamp);

    [LoggerMessage(EventId = 2, Level = LogLevel.Debug, Message = "Hawk request signed. Id={Id} Method={Method} Uri={Uri} Timestamp={Timestamp} App={App} Dlg={Dlg}")]
    public static partial void HawkRequestSigned(ILogger logger, string id, string method, Uri? uri, long timestamp, string? app, string? dlg);

    [LoggerMessage(EventId = 3, Level = LogLevel.Warning, Message = "Hawk server authorization validation failed: unexpected parameter count {Count}. Uri={Uri}")]
    public static partial void HawkServerAuthorizationUnexpectedParameterCount(ILogger logger, int count, Uri? uri);

    [LoggerMessage(EventId = 4, Level = LogLevel.Warning, Message = "Hawk server authorization validation failed: missing mac. Uri={Uri}")]
    public static partial void HawkServerAuthorizationMissingMac(ILogger logger, Uri? uri);

    [LoggerMessage(EventId = 5, Level = LogLevel.Warning, Message = "Hawk server authorization validation failed: bad mac. Uri={Uri}")]
    public static partial void HawkServerAuthorizationBadMac(ILogger logger, Uri? uri);

    [LoggerMessage(EventId = 6, Level = LogLevel.Warning, Message = "Hawk server authorization validation failed: bad payload hash. Uri={Uri}")]
    public static partial void HawkServerAuthorizationBadPayloadHash(ILogger logger, Uri? uri);

    [LoggerMessage(EventId = 7, Level = LogLevel.Warning, Message = "Hawk server timestamp validation failed. ServerTimestamp={ServerTimestamp} CurrentOffsetSeconds={Offset}")]
    public static partial void HawkServerTimestampValidationFailed(ILogger logger, long serverTimestamp, long offset);
}
