namespace Alastack.HmacAuth;

/// <summary>
/// Authentication header
/// </summary>
public class AuthenticationHeader
{
    /// <summary>
    /// Authentication header name.
    /// </summary>
    public string HeaderName { get; set; } = "Authorization";

    /// <summary>
    /// Authentication scheme.
    /// </summary>
    public string Scheme { get; set; } = default!;

    /// <summary>
    /// Authentication parameter.
    /// </summary>
    public string Parameter { get; set; } = default!;

    /// <summary>
    /// Authentication properties.
    /// </summary>
    public IDictionary<string, object> Properties { get; } = new Dictionary<string, object>();

    /// <summary>
    /// Generic header name flag.
    /// </summary>
    public bool IsGenericHeaderName
    {
        get => HeaderName == "Authorization";
    }
}