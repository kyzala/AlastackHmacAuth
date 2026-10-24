using Alastack.HmacAuth;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Text;

namespace Alastack.HmacAuth.Options;

/// <summary>
/// The <see cref="HawkDelegatingHandler"/> implementation that supplies its settings from
/// <see cref="IOptionsMonitor{T}"/>, so configuration changes are picked up at runtime.
/// </summary>
public class OptionsHawkDelegatingHandler : HawkDelegatingHandler
{
    private readonly IOptionsMonitor<HawkSettings> _optionsMonitor;

    /// <inheritdoc />
    public override HawkSettings Settings => _optionsMonitor.CurrentValue;

    /// <summary>
    /// Initializes a new instance of <see cref="OptionsHawkDelegatingHandler"/>.
    /// </summary>
    /// <param name="optionsMonitor">Used for notifications when <see cref="HawkSettings"/> instances change.</param>
    public OptionsHawkDelegatingHandler(IOptionsMonitor<HawkSettings> optionsMonitor)
    {
        _optionsMonitor = optionsMonitor;
    }
}
