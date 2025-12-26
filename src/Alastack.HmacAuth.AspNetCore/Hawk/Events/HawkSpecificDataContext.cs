using Microsoft.AspNetCore.Http;

namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// Contains information about setting Hawk authentication specific data.
/// </summary>
public class HawkSpecificDataContext
{
    /// <summary>
    /// The HTTP environment.
    /// </summary>
    public HttpContext HttpContext { get; }

    /// <summary>
    /// The options used by the authentication middleware.
    /// </summary>
    public HawkOptions Options { get; }

    /// <summary>
    /// Hawk authentication credential.
    /// </summary>
    public HawkCredential Credential { get; }

    /// <summary>
    /// Hawk authentication specific data.
    /// </summary>
    public string? Data { get; set; }

    /// <summary>
    /// Initializes a new instance of <see cref="HawkSpecificDataContext"/>.
    /// </summary>
    /// <param name="httpContext">The HTTP environment.</param>
    /// <param name="options">The options used by the authentication middleware.</param>
    /// <param name="credential">Hawk authentication credential.</param>
    public HawkSpecificDataContext(HttpContext httpContext, HawkOptions options, HawkCredential credential) 
    {
        HttpContext = httpContext;
        Options = options;
        Credential = credential;
    }
}
