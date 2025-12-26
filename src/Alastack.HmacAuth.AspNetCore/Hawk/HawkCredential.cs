namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// Hawk authentication credential.
/// </summary>
public class HawkCredential
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
    /// The user name associated with the authentication Id.
    /// </summary>
    public string? User { get; set; }

    /// <summary>
    /// Whether to enable server-authentication for the authentication Id.
    /// </summary>
    public bool EnableServerAuthorization { get; set; }

    /// <summary>
    /// Whether to include the hash value of the Http response payload when server-authentication is enabled for the authentication Id.
    /// </summary>
    public bool IncludeResponsePayloadHash { get; set; }
}