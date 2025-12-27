using System.Text;

namespace Alastack.HmacAuth;

/// <summary>
/// Extension methods for ICryptoFactory
/// </summary>
public static class CryptoFactoryExtensions
{
    //public static ICrypto Create(this ICryptoFactory factory, string algorithmName, string key)
    //{
    //    if (String.IsNullOrWhiteSpace(key))
    //    {
    //        throw new ArgumentNullException(nameof(key));
    //    }
    //    var buffer = Encoding.UTF8.GetBytes(key);
    //    return factory.Create(algorithmName, buffer);
    //}

    //public static ICrypto Create(this ICryptoFactory factory, string algorithmName, byte[] key)
    //{
    //    if (String.IsNullOrWhiteSpace(algorithmName))
    //    {
    //        throw new ArgumentNullException(nameof(algorithmName));
    //    }
    //    var hmacAlgorithmName = $"HMAC{algorithmName}".ToUpperInvariant();
    //    var hashAlgorithmName = algorithmName.ToUpperInvariant();
    //    return factory.Create(hmacAlgorithmName, hashAlgorithmName, key);
    //}

    /// <summary>
    /// Creates a cryptographic instance using a string key
    /// </summary>
    /// <param name="factory">The cryptographic factory</param>
    /// <param name="hmacAlgorithmName">HMAC algorithm name</param>
    /// <param name="hashAlgorithmName">Hash algorithm name</param>
    /// <param name="key">String key</param>
    /// <returns>Cryptographic instance</returns>
    /// <exception cref="ArgumentNullException">Thrown when key is null or empty</exception>
    public static ICrypto Create(this ICryptoFactory factory, string hmacAlgorithmName, string hashAlgorithmName, string key)
    {
        if (String.IsNullOrWhiteSpace(key))
        {
            throw new ArgumentNullException(nameof(key), "A valid key is required to ensure cryptographic security");
        }
        var buffer = Encoding.UTF8.GetBytes(key);
        return factory.Create(hmacAlgorithmName, hashAlgorithmName, buffer);
    }
}