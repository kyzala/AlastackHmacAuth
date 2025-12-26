using System.Security.Claims;

namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// Specifies events which the <see cref="HawkHandler"/> invokes to enable developer control over the authentication process.
/// </summary>
public class HawkEvents
{
    /// <summary>
    /// Gets or sets the function that is invoked when the CreatingTicket method is invoked.
    /// </summary>
    public Func<HawkCreatingTicketContext, Task> OnCreatingTicket { get; set; } = context => Task.CompletedTask;

    /// <summary>
    /// Invoked after the client has been successfully authenticated.
    /// </summary>
    /// <param name="context">Contains information about the login session as well as the client <see cref="ClaimsIdentity"/>.</param>
    /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
    public virtual Task CreatingTicket(HawkCreatingTicketContext context) => OnCreatingTicket(context);

    /// <summary>
    /// Gets or sets the function that is invoked when the SetSpecificData method is invoked.
    /// </summary>
    public Func<HawkSpecificDataContext, Task> OnSetSpecificData { get; set; } = context => Task.CompletedTask;

    /// <summary>
    /// Called when setting Hawk authentication specific data.
    /// </summary>
    /// <param name="context">Contains information about setting Hawk authentication specific data.</param>
    /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
    public virtual Task SetSpecificData(HawkSpecificDataContext context) => OnSetSpecificData(context);
}
