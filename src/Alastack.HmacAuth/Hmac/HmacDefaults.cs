namespace Alastack.HmacAuth;

/// <summary>
/// Default values for the Hmac authentication.
/// </summary>
public static class HmacDefaults
{
    /// <summary>
    /// The default scheme for Hmac authentication. The value is <c>Hmac</c>.
    /// </summary>
    public const string AuthenticationScheme = "Hmac";

    /// <summary>
    /// The default display name for Hmac authentication. Defaults to <c>HmacAuthentication</c>.
    /// </summary>
    public const string DisplayName = "HmacAuthentication";

    /// <summary>
    /// The Hmac authentication version. The value is <c>1</c>.
    /// </summary>
    public const string Version = "1";
}