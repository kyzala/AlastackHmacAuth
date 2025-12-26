namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// A data cache abstraction.
/// </summary>
public interface IDataCache
{
    /// <summary>
    /// Gets a value with the given key.
    /// </summary>
    /// <param name="key">A string identifying the requested value.</param>
    /// <param name="token">Optional. A <see cref="CancellationToken" /> to cancel the operation.</param>
    /// <returns>Task that represents the asynchronous operation, containing the located value or null.</returns>
    Task<byte[]?> GetAsync(string key, CancellationToken token = default);

    /// <summary>
    /// Sets the value with the given key.
    /// </summary>
    /// <param name="key">A string identifying the requested value.</param>
    /// <param name="value">The value to set in the cache.</param>
    /// <param name="absoluteExpirationRelativeToNow">Absolute expiration relative to now.</param>
    /// <param name="token">Optional. A <see cref="CancellationToken" /> to cancel the operation.</param>
    /// <returns>Task that represents the asynchronous operation.</returns>
    Task SetAsync(string key, byte[] value, TimeSpan absoluteExpirationRelativeToNow, CancellationToken token = default);
}