namespace Alastack.HmacAuth;

/// <summary>
/// Default values for the Hawk authentication.
/// </summary>
public static class HawkDefaults
{
    /// <summary>
    /// The default scheme for Hawk authentication. The value is <c>Hawk</c>.
    /// </summary>
    public const string AuthenticationScheme = "Hawk";

    /// <summary>
    /// The default display name for Hawk authentication. Defaults to <c>HawkAuthentication</c>.
    /// </summary>
    public const string DisplayName = "HawkAuthentication";

    /// <summary>
    /// The Hawk authentication version. The value is <c>1</c>.
    /// </summary>
    public const string Version = "1";
}