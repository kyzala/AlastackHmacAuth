using Alastack.HmacAuth;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Text;

namespace Alastack.HmacAuth.Options;

/// <summary>
/// The <see cref="HmacDelegatingHandler"/> implementation that supplies its settings from
/// <see cref="IOptionsMonitor{T}"/>, so configuration changes are picked up at runtime.
/// </summary>
public class OptionsHmacDelegatingHandler : HmacDelegatingHandler
{
    private readonly IOptionsMonitor<HmacSettings> _optionsMonitor;

    /// <inheritdoc />
    public override HmacSettings Settings => _optionsMonitor.CurrentValue;

    /// <summary>
    /// Initializes a new instance of <see cref="OptionsHmacDelegatingHandler"/>.
    /// </summary>
    /// <param name="optionsMonitor">Used for notifications when <see cref="HmacSettings"/> instances change.</param>
    public OptionsHmacDelegatingHandler(IOptionsMonitor<HmacSettings> optionsMonitor)
    {
        _optionsMonitor = optionsMonitor;
    }
}
