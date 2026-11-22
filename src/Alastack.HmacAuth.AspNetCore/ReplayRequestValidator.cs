using Microsoft.Extensions.Logging;

namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// The default implementation of <see cref="IReplayRequestValidator"/>.
/// </summary>
public class ReplayRequestValidator : IReplayRequestValidator
{
    private readonly IDataCache _dataCache;

    private readonly ILogger? _logger;

    /// <summary>
    /// Initializes a new instance of <see cref="ReplayRequestValidator"/>.
    /// </summary>
    /// <param name="dataCache"><see cref="IDataCache"/></param>
    /// <param name="logger">The optional logger.</param>
    public ReplayRequestValidator(IDataCache dataCache, ILogger? logger = null)
    {
        _dataCache = dataCache;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<bool> ValidateAsync(string id, string nonce, long timestamp, long maxReplayRequestAge, CancellationToken cancellationToken = default)
    {
        if (maxReplayRequestAge == 0)
        {
            return false;
        }
        var val = await _dataCache.GetAsync(id, cancellationToken);
        if (val != null)
        {
            _logger?.LogWarning("Replay request detected. Key={Key} Nonce={Nonce} Timestamp={Timestamp}", id, nonce, timestamp);
            return true;
        }
        //var data = Encoding.UTF8.GetBytes(timestamp.ToString());
        await _dataCache.SetStringAsync(id, timestamp.ToString(), TimeSpan.FromSeconds(maxReplayRequestAge), cancellationToken);
        return false;
    }
}