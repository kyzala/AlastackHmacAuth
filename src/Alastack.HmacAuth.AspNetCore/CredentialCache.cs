using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// The common implementation of <see cref="ICredentialCache{TCredential}"/>.
/// </summary>
/// <typeparam name="TCredential">A credential type.</typeparam>
public class CredentialCache<TCredential> : ICredentialCache<TCredential>
{
    private readonly IDataCache _dataCache;

    private readonly ILogger _logger;

    private readonly JsonSerializerOptions _options = new()
    {
        PropertyNameCaseInsensitive = false,
        PropertyNamingPolicy = null,//JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        IgnoreReadOnlyProperties = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Initializes a new instance of <see cref="CredentialCache{TCredential}"/>.
    /// </summary>
    /// <param name="dataCache"><see cref="IDataCache"/></param>
    /// <param name="logger">The optional logger.</param>
    public CredentialCache(IDataCache dataCache, ILogger? logger = null) 
    {            
        _dataCache = dataCache;
        _logger = logger ?? NullLogger.Instance;
    }

    /// <inheritdoc />
    public async Task<TCredential?> GetCredentialAsync(string key, CancellationToken cancellationToken = default)
    {
        var data = await _dataCache.GetStringAsync(key, cancellationToken);
        if (data != null) 
        {
            ServerLogMessages.CredentialCacheHit(_logger, key);
            return JsonSerializer.Deserialize<TCredential>(data, _options);
        }
        ServerLogMessages.CredentialCacheMiss(_logger, key);
        return default;
    }

    /// <inheritdoc />
    public async Task SetCredentialAsync(string key, TCredential credential, long cacheTime, CancellationToken cancellationToken = default)
    {
        var data = JsonSerializer.Serialize<TCredential>(credential, _options);
        await _dataCache.SetStringAsync(key, data, TimeSpan.FromSeconds(cacheTime), cancellationToken);
        ServerLogMessages.CredentialCached(_logger, key, cacheTime);
    }
}
