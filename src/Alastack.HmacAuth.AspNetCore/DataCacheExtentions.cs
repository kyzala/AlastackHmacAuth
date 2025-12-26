using System.Text;

namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// DataCache extentions.
/// </summary>
public static class DataCacheExtentions
{
    /// <summary>
    /// Gets a string value with the given key.
    /// </summary>
    /// <param name="cache"><see cref="IDataCache"/> instance.</param>
    /// <param name="key">A string identifying the requested value.</param>
    /// <param name="token">Optional. A <see cref="CancellationToken" /> to cancel the operation.</param>
    /// <returns>Task that represents the asynchronous operation, containing the located value or null.</returns>
    public static async Task<string?> GetStringAsync(this IDataCache cache, string key, CancellationToken token = default)
    {
        byte[]? data = await cache.GetAsync(key, token).ConfigureAwait(false);
        if (data == null)
        {
            return null;
        }
        return Encoding.UTF8.GetString(data, 0, data.Length);
    }

    /// <summary>
    /// Sets the string value with the given key.
    /// </summary>
    /// <param name="cache"><see cref="IDataCache"/> instance.</param>
    /// <param name="key">A string identifying the requested value.</param>
    /// <param name="value">The value to set in the cache.</param>
    /// <param name="absoluteExpirationRelativeToNow">Absolute expiration relative to now.</param>
    /// <param name="token">Optional. A <see cref="CancellationToken" /> to cancel the operation.</param>
    /// <returns>Task that represents the asynchronous operation.</returns>
    public static async Task SetStringAsync(this IDataCache cache, string key, string value, TimeSpan absoluteExpirationRelativeToNow, CancellationToken token = default) 
    {
        await cache.SetAsync(key, Encoding.UTF8.GetBytes(value), absoluteExpirationRelativeToNow, token);
    }
}
