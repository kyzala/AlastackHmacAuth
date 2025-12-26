using System.Security.Claims;

namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// Specifies events which the <see cref="HmacHandler"/> invokes to enable developer control over the authentication process.
/// </summary>
public class HmacEvents
{
    /// <summary>
    /// Gets or sets the function that is invoked when the CreatingTicket method is invoked.
    /// </summary>
    public Func<HmacCreatingTicketContext, Task> OnCreatingTicket { get; set; } = context => Task.CompletedTask;

    /// <summary>
    /// Invoked after the client has been successfully authenticated.
    /// </summary>
    /// <param name="context">Contains information about the login session as well as the client <see cref="ClaimsIdentity"/>.</param>
    /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
    public virtual Task CreatingTicket(HmacCreatingTicketContext context) => OnCreatingTicket(context);
}
