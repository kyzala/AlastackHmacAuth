namespace Alastack.HmacAuth;

/// <summary>
/// Hawk authentication settings for <see cref="HawkDelegatingHandler"/>.
/// </summary>
public class HawkSettings
{
    /// <summary>
    /// The authentication Id.
    /// </summary>
    public string AuthId { get; set; } = default!;

    /// <summary>
    /// The authentication key.
    /// </summary>
    public string AuthKey { get; set; } = default!;

    /// <summary>
    /// The HMAC(Hash-based Message Authentication Code) algorithm name. Defaults to <c>HMACSHA256</c>.
    /// </summary>
    public string HmacAlgorithm { get; set; } = "HMACSHA256";

    /// <summary>
    /// The hash algorithm name. Defaults to <c>SHA256</c>.
    /// </summary>
    public string HashAlgorithm { get; set; } = "SHA256";

    /// <summary>
    /// Whether to include the hash value of the Http request payload when sending the request.
    /// </summary>
    public bool IncludePayloadHash { get; set; } = true;

    /// <summary>
    /// Set the offset(in seconds) to synchronize with the server time. Defaults to <c>0</c> second.
    /// </summary>
    public long TimeOffset { get; set; }

    /// <summary>
    /// The binding between credential and the application to prevent an attacker using credential issued to someone else.
    /// </summary>
    public string? App { get; set; }

    /// <summary>
    /// The Id of the application the credential were issued to.
    /// </summary>
    public string? Dlg { get; set; }

    /// <summary>
    /// Whether to enable server-authentication validation.
    /// </summary>
    public bool EnableServerAuthorizationValidation { get; set; }

    /// <summary>
    /// Whether to enable server time validation.
    /// </summary>
    public bool EnableServerTimeValidation { get; set; }

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

    /// <summary>
    /// <see cref="IAuthorizationParameterExtractor"/> interface. The default implementation is <see cref="HawkParameterExtractor"/>.
    /// </summary>
    public IAuthorizationParameterExtractor AuthorizationParameterExtractor { get; set; } = new HawkParameterExtractor();

    /// <summary>
    /// Gets or sets the function to get Hawk authentication specific data.
    /// </summary>
    public Func<HttpRequestMessage, HawkSettings, Task<string?>> GetSpecificData { get; set; } = (request, options) => Task.FromResult((string?)null);
}