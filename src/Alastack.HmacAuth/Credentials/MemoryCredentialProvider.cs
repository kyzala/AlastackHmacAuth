namespace Alastack.HmacAuth.Credentials;

/// <summary>
/// The in-memory implementation of <see cref="ICredentialProvider{TCredential}"/>.
/// </summary>
/// <typeparam name="TCredential">a credential type.</typeparam>
public class MemoryCredentialProvider<TCredential> : ICredentialProvider<TCredential>
{
    private readonly IDictionary<string, TCredential> _credentialData;

    /// <summary>
    /// Inited credential data.
    /// </summary>
    public IDictionary<string, TCredential> CredentialData => _credentialData;

    /// <summary>
    /// Initializes a new instance of <see cref="MemoryCredentialProvider{TCredential}"/>.
    /// </summary>
    /// <param name="credentialData">Inited credential data.</param>
    public MemoryCredentialProvider(IDictionary<string, TCredential> credentialData)
    {
        _credentialData = credentialData;
    }

    /// <inheritdoc />
    public async Task<TCredential?> GetCredentialAsync(string id, CancellationToken token = default)
    {
        if (_credentialData.TryGetValue(id, out TCredential? credential))
        {
            return await Task.FromResult<TCredential?>(credential);
        }
        return await Task.FromResult(default(TCredential?));
    }
}