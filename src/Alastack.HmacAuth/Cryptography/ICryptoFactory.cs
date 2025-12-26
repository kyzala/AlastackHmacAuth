namespace Alastack.HmacAuth;

/// <summary>
/// A factory abstraction for a component that can create <see cref="ICrypto"/> instances.
/// </summary>
public interface ICryptoFactory
{
    /// <summary>
    /// Create a <see cref="ICrypto"/> instanse.
    /// </summary>
    /// <param name="hmacAlgorithmName">The HMAC(Hash-based Message Authentication Code) algorithm name.</param>
    /// <param name="hashAlgorithmName">The hash algorithm name.</param>
    /// <param name="key">The key to use in the HMAC calculation.</param>
    /// <returns>A <see cref="ICrypto"/> instanse for computing hashes.</returns>
    ICrypto Create(string hmacAlgorithmName, string hashAlgorithmName, byte[] key);
}