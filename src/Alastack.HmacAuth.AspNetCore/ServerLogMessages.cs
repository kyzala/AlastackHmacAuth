using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// Source-generated log messages for the server authentication pipeline.
/// </summary>
internal static partial class ServerLogMessages
{
    [LoggerMessage(EventId = 1, Level = LogLevel.Information, Message = "Authentication failed: missing Authorization header. Scheme={Scheme} Path={Path}")]
    public static partial void MissingAuthorizationHeader(ILogger logger, string scheme, PathString path);

    [LoggerMessage(EventId = 2, Level = LogLevel.Information, Message = "Authentication failed: invalid authorization scheme. Scheme={Scheme} Path={Path}")]
    public static partial void InvalidAuthorizationScheme(ILogger logger, string scheme, PathString path);

    [LoggerMessage(EventId = 3, Level = LogLevel.Information, Message = "Authentication failed: expected {Expected} authorization parameters but found {Count}. Scheme={Scheme} Path={Path}")]
    public static partial void UnexpectedParameterCount(ILogger logger, int expected, int count, string scheme, PathString path);

    [LoggerMessage(EventId = 4, Level = LogLevel.Error, Message = "Invalid authorization parameters. Scheme={Scheme} Path={Path}")]
    public static partial void InvalidAuthorizationParameters(ILogger logger, Exception exception, string scheme, PathString path);

    [LoggerMessage(EventId = 5, Level = LogLevel.Warning, Message = "Authentication rejected: replay request. Scheme={Scheme} Id={Id} Nonce={Nonce}")]
    public static partial void ReplayRequestRejected(ILogger logger, string scheme, string id, string nonce);

    [LoggerMessage(EventId = 6, Level = LogLevel.Warning, Message = "Authentication failed: credential not found or incomplete. Scheme={Scheme} Id={Id}")]
    public static partial void CredentialNotFound(ILogger logger, string scheme, string id);

    [LoggerMessage(EventId = 7, Level = LogLevel.Information, Message = "Authentication failed: stale timestamp. Scheme={Scheme} Id={Id} ClientTimestamp={ClientTimestamp} ServerTimestamp={ServerTimestamp} TimeSkew={TimeSkew}")]
    public static partial void StaleTimestamp(ILogger logger, string scheme, string id, long clientTimestamp, long serverTimestamp, long timeSkew);

    [LoggerMessage(EventId = 8, Level = LogLevel.Warning, Message = "Authentication failed: bad MAC. Scheme={Scheme} Id={Id} Path={Path}")]
    public static partial void BadMac(ILogger logger, string scheme, string id, PathString path);

    [LoggerMessage(EventId = 9, Level = LogLevel.Warning, Message = "Authentication failed: bad payload hash. Scheme={Scheme} Id={Id} Path={Path}")]
    public static partial void BadPayloadHash(ILogger logger, string scheme, string id, PathString path);

    [LoggerMessage(EventId = 10, Level = LogLevel.Error, Message = "Credential provider failed. Scheme={Scheme} Id={Id}")]
    public static partial void CredentialProviderFailed(ILogger logger, Exception exception, string scheme, string id);

    [LoggerMessage(EventId = 11, Level = LogLevel.Warning, Message = "Replay request detected. Key={Key} Nonce={Nonce} Timestamp={Timestamp}")]
    public static partial void ReplayRequestDetected(ILogger logger, string key, string nonce, long timestamp);

    [LoggerMessage(EventId = 12, Level = LogLevel.Debug, Message = "Credential cache hit. Key={Key}")]
    public static partial void CredentialCacheHit(ILogger logger, string key);

    [LoggerMessage(EventId = 13, Level = LogLevel.Debug, Message = "Credential cache miss. Key={Key}")]
    public static partial void CredentialCacheMiss(ILogger logger, string key);

    [LoggerMessage(EventId = 14, Level = LogLevel.Debug, Message = "Credential cached. Key={Key} CacheTime={CacheTime}s")]
    public static partial void CredentialCached(ILogger logger, string key, long cacheTime);

    [LoggerMessage(EventId = 15, Level = LogLevel.Debug, Message = "Hawk Server-Authorization added. Id={Id} Path={Path}")]
    public static partial void ServerAuthorizationAdded(ILogger logger, string id, PathString path);

    [LoggerMessage(EventId = 16, Level = LogLevel.Error, Message = "Failed to add Hawk server authorization. Path={Path}")]
    public static partial void ServerAuthorizationFailed(ILogger logger, Exception exception, PathString path);
}
