using System.Text.Json;
using System.Text.Json.Serialization;

namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// The common implementation of <see cref="ICredentialCache{TCredential}"/>.
/// </summary>
/// <typeparam name="TCredential">A credential type.</typeparam>
public class CredentialCache<TCredential> : ICredentialCache<TCredential>
{
    private readonly IDataCache _dataCache;

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
    public CredentialCache(IDataCache dataCache) 
    {            
        _dataCache = dataCache;
    }

    /// <inheritdoc />
    public async Task<TCredential?> GetCredentialAsync(string key, CancellationToken token = default)
    {
        var data = await _dataCache.GetStringAsync(key, token);
        if (data != null) 
        {
            return JsonSerializer.Deserialize<TCredential>(data, _options);
        }
        return default;
    }

    /// <inheritdoc />
    public async Task SetCredentialAsync(string key, TCredential credential, long cacheTime, CancellationToken token = default)
    {
        var data = JsonSerializer.Serialize<TCredential>(credential, _options);
        await _dataCache.SetStringAsync(key, data, TimeSpan.FromSeconds(cacheTime), token);
    }
}
