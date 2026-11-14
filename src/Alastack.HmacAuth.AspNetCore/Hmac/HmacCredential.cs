namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// Hmac authentication credential.
/// </summary>
public class HmacCredential
{
    /// <summary>
    /// The app Id.
    /// </summary>
    public string AppId { get; set; } = default!;

    /// <summary>
    /// The app secret used as the shared key for signing.
    /// </summary>
    public string AppSecret { get; set; } = default!;

    /// <summary>
    /// The HMAC(Hash-based Message Authentication Code) algorithm name. Defaults to <c>HMACSHA256</c>.
    /// </summary>
    public string HmacAlgorithm { get; set; } = "HMACSHA256";

    /// <summary>
    /// The hash algorithm name. Defaults to <c>SHA256</c>.
    /// </summary>
    public string HashAlgorithm { get; set; } = "SHA256";
}