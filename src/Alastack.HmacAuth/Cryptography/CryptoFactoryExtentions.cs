using System.Text;

namespace Alastack.HmacAuth;

public static class CryptoFactoryExtentions
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

    public static ICrypto Create(this ICryptoFactory factory, string hmacAlgorithmName, string hashAlgorithmName, string key)
    {
        if (String.IsNullOrWhiteSpace(key))
        {
            throw new ArgumentNullException(nameof(key));
        }
        var buffer = Encoding.UTF8.GetBytes(key);
        return factory.Create(hmacAlgorithmName, hashAlgorithmName, buffer);
    }
}