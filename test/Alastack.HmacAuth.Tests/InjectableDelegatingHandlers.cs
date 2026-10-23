using Microsoft.Extensions.Options;

namespace Alastack.HmacAuth.Tests;

/// <summary>
/// <see cref="HmacDelegatingHandler"/> whose settings come from <see cref="IOptionsMonitor{T}"/>,
/// for DI-based client tests.
/// </summary>
public class InjectableHmacDelegatingHandler : HmacDelegatingHandler
{
    private readonly IOptionsMonitor<HmacSettings> _optionsMonitor;

    public override HmacSettings Settings => _optionsMonitor.CurrentValue;

    public InjectableHmacDelegatingHandler(IOptionsMonitor<HmacSettings> optionsMonitor)
    {
        _optionsMonitor = optionsMonitor;
    }
}

/// <summary>
/// <see cref="HawkDelegatingHandler"/> whose settings come from <see cref="IOptionsMonitor{T}"/>,
/// for DI-based client tests.
/// </summary>
public class InjectableHawkDelegatingHandler : HawkDelegatingHandler
{
    private readonly IOptionsMonitor<HawkSettings> _optionsMonitor;

    public override HawkSettings Settings => _optionsMonitor.CurrentValue;

    public InjectableHawkDelegatingHandler(IOptionsMonitor<HawkSettings> optionsMonitor)
    {
        _optionsMonitor = optionsMonitor;
    }
}
