namespace Alastack.HmacAuth.Credentials;

/// <summary>
/// A credential provider abstraction.
/// </summary>
/// <typeparam name="TCredential">a credential type.</typeparam>
public interface ICredentialProvider<TCredential>
{
    /// <summary>
    /// Gets a credential with the given id.
    /// </summary>
    /// <param name="id">credential id</param>
    /// <param name="token">Optional. A <see cref="CancellationToken" /> to cancel the operation.</param>
    /// <returns>The task object representing the asynchronous operation, containing the located value or null.</returns>
    Task<TCredential?> GetCredentialAsync(string id, CancellationToken token = default);
}