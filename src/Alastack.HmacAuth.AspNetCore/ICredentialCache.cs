namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// A credential cache abstraction.
/// </summary>
/// <typeparam name="TCredential">a credential type.</typeparam>
public interface ICredentialCache<TCredential>
{
    /// <summary>
    /// Gets a credential with the given id.
    /// </summary>
    /// <param name="key">credential cache key</param>
    /// <param name="token">Optional. A <see cref="CancellationToken" /> to cancel the operation.</param>
    /// <returns>The task object representing the asynchronous operation, containing the located value or null.</returns>
    Task<TCredential?> GetCredentialAsync(string key, CancellationToken token = default);

    /// <summary>
    /// Sets the credential with the given key.
    /// </summary>
    /// <param name="key">credential cache key</param>
    /// <param name="credential">credential instance.</param>
    /// <param name="cacheTime">credential cache time.</param>
    /// <param name="token">Optional. A <see cref="CancellationToken" /> to cancel the operation.</param>
    /// <returns>Task that represents the asynchronous operation.</returns>
    Task SetCredentialAsync(string key, TCredential credential, long cacheTime, CancellationToken token = default);
}
