namespace Alastack.HmacAuth;

/// <summary>
/// Hmac authentication settings for <see cref="HmacDelegatingHandler"/>.
/// </summary>
public class HmacSettings
{
    /// <summary>
    /// The app Id.
    /// </summary>
    public string AppId { get; set; } = default!;

    /// <summary>
    /// The app key.
    /// </summary>
    public string AppKey { get; set; } = default!;

    /// <summary>
    /// The HMAC(Hash-based Message Authentication Code) algorithm name. Defaults to <c>HMACSHA256</c>.
    /// </summary>
    public string HmacAlgorithm { get; set; } = "HMACSHA256";

    /// <summary>
    /// The hash algorithm name. Defaults to <c>MD5</c>.
    /// </summary>
    public string HashAlgorithm { get; set; } = "MD5";

    /// <summary>
    /// Whether to include the hash value of the Http request payload when sending the request.
    /// </summary>
    public bool IncludePayloadHash { get; set; } = true;

    /// <summary>
    /// Set the offset(in seconds) to synchronize with the server time. Defaults to <c>0</c> second.
    /// </summary>
    public long TimeOffset { get; set; }

    /// <summary>
    /// <see cref="ICryptoFactory"/> interface. The default implementation is <see cref="DefaultCryptoFactory"/>.
    /// </summary>
    public ICryptoFactory CryptoFactory { get; set; } = new DefaultCryptoFactory();

    /// <summary>
    /// <see cref="ITimestampCalculator"/> interface. The default implementation is <see cref="Alastack.HmacAuth.TimestampCalculator"/>.
    /// </summary>
    public ITimestampCalculator TimestampCalculator { get; set; } = new TimestampCalculator();

    /// <summary>
    /// <see cref="INonceGenerator"/> interface. The default implementation is <see cref="Alastack.HmacAuth.NonceGenerator"/>.
    /// </summary>
    public INonceGenerator NonceGenerator { get; set; } = new NonceGenerator();
}