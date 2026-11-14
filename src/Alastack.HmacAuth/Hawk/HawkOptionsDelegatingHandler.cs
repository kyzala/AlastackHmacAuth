using Microsoft.Extensions.Options;

namespace Alastack.HmacAuth;

/// <summary>
/// The <see cref="HawkDelegatingHandler"/> implementation that supplies its settings from
/// <see cref="IOptionsMonitor{T}"/>, so configuration changes are picked up at runtime.
/// </summary>
public class HawkOptionsDelegatingHandler : HawkDelegatingHandler
{
    private readonly IOptionsMonitor<HawkSettings> _optionsMonitor;

    /// <inheritdoc />
    public override HawkSettings Settings => _optionsMonitor.CurrentValue;

    /// <summary>
    /// Initializes a new instance of <see cref="HawkOptionsDelegatingHandler"/>.
    /// </summary>
    /// <param name="optionsMonitor">Used for notifications when <see cref="HawkSettings"/> instances change.</param>
    public HawkOptionsDelegatingHandler(IOptionsMonitor<HawkSettings> optionsMonitor)
    {
        _optionsMonitor = optionsMonitor;
    }
}
