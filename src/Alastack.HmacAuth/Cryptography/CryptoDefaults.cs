namespace Alastack.HmacAuth;

/// <summary>
/// Crypto defaults
/// </summary>
public static class CryptoDefaults
{
    /// <summary>
    /// HMAC algorithm names.
    /// </summary>
    public static readonly string[] HMACAlgorithmNames = new[] { "HMACMD5", "HMACSHA1", "HMACSHA256", "HMACSHA384", "HMACSHA512" };

    /// <summary>
    /// Hash algorithm names.
    /// </summary>
    public static readonly string[] HashAlgorithmNames = new[] { "MD5", "SHA1", "SHA256", "SHA384", "SHA512" };
}