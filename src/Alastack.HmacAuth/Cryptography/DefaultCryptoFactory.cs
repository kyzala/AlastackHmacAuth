namespace Alastack.HmacAuth;

/// <summary>
/// The default implementation of <see cref="ICryptoFactory"/>.
/// </summary>
public class DefaultCryptoFactory : ICryptoFactory
{
    /// <inheritdoc />
    public ICrypto Create(string hmacAlgorithmName, string hashAlgorithmName, byte[] key)
    {
        if (String.IsNullOrWhiteSpace(hmacAlgorithmName))
        {
            throw new ArgumentNullException(nameof(hmacAlgorithmName));
        }
        if (String.IsNullOrWhiteSpace(hashAlgorithmName))
        {
            throw new ArgumentNullException(nameof(hashAlgorithmName));
        }
        var hmacName = hmacAlgorithmName.ToUpperInvariant();
        if (!CryptoDefaults.HMACAlgorithmNames.Contains(hmacName))
        {
            throw new ArgumentException($"The hmacAlgorithmName parameter is error.", nameof(hmacAlgorithmName));
        }
        var hashName = hashAlgorithmName.ToUpperInvariant();
        if (!CryptoDefaults.HashAlgorithmNames.Contains(hashName))
        {
            throw new ArgumentException($"The hashAlgorithmName parameter is error.", nameof(hashAlgorithmName));
        }
        return new DefaultCrypto(hmacName, hashName, key);
    }
}