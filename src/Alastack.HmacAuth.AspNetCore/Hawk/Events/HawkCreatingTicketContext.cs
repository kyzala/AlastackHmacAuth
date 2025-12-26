using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// Contains information about the login session as well as the client <see cref="ClaimsIdentity"/>.
/// </summary>
public class HawkCreatingTicketContext : ResultContext<HawkOptions>
{
    /// <summary>
    /// Gets the main identity exposed by the authentication ticket.
    /// This property returns <c>null</c> when the ticket is <c>null</c>.
    /// </summary>
    public ClaimsIdentity? Identity => Principal?.Identity as ClaimsIdentity;

    /// <summary>
    /// Initializes a new instance of <see cref="HawkCreatingTicketContext"/>.
    /// </summary>
    /// <param name="principal">The <see cref="ClaimsPrincipal"/>.</param>
    /// <param name="properties">The <see cref="AuthenticationProperties"/>.</param>
    /// <param name="context">The HTTP environment.</param>
    /// <param name="scheme">The authentication scheme.</param>
    /// <param name="options">The options used by the authentication middleware.</param>
    public HawkCreatingTicketContext(
        ClaimsPrincipal principal,
        AuthenticationProperties properties, 
        HttpContext context, 
        AuthenticationScheme scheme, 
        HawkOptions options)
        : base(context, scheme, options)
    {
        Principal = principal;
        Properties = properties;
    }
}
