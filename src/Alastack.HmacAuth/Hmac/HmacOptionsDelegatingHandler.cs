using Microsoft.Extensions.Options;

namespace Alastack.HmacAuth;

/// <summary>
/// The <see cref="HmacDelegatingHandler"/> implementation that supplies its settings from
/// <see cref="IOptionsMonitor{T}"/>, so configuration changes are picked up at runtime.
/// </summary>
public class HmacOptionsDelegatingHandler : HmacDelegatingHandler
{
    private readonly IOptionsMonitor<HmacSettings> _optionsMonitor;

    /// <inheritdoc />
    public override HmacSettings Settings => _optionsMonitor.CurrentValue;

    /// <summary>
    /// Initializes a new instance of <see cref="HmacOptionsDelegatingHandler"/>.
    /// </summary>
    /// <param name="optionsMonitor">Used for notifications when <see cref="HmacSettings"/> instances change.</param>
    public HmacOptionsDelegatingHandler(IOptionsMonitor<HmacSettings> optionsMonitor)
    {
        _optionsMonitor = optionsMonitor;
    }
}
