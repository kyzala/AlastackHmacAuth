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
}