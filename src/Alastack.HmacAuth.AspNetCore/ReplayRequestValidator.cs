namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// The default implementation of <see cref="IReplayRequestValidator"/>.
/// </summary>
public class ReplayRequestValidator : IReplayRequestValidator
{
    private readonly IDataCache _dataCache;

    /// <summary>
    /// Initializes a new instance of <see cref="ReplayRequestValidator"/>.
    /// </summary>
    /// <param name="dataCache"><see cref="IDataCache"/></param>
    public ReplayRequestValidator(IDataCache dataCache)
    {
        _dataCache = dataCache;
    }

    /// <inheritdoc />
    public async Task<bool> ValidateAsync(string id, string nonce, long timestamp, long maxReplayRequestAge, CancellationToken token = default)
    {
        if (maxReplayRequestAge == 0)
        {
            return false;
        }
        var val = await _dataCache.GetAsync(id, token);
        if (val != null)
        {
            return true;
        }
        //var data = Encoding.UTF8.GetBytes(timestamp.ToString());
        await _dataCache.SetStringAsync(id, timestamp.ToString(), TimeSpan.FromSeconds(maxReplayRequestAge), token);
        return false;
    }
}