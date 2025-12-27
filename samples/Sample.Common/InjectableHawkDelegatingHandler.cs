using Alastack.HmacAuth;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Text;

namespace Sample.Common;

/// <summary>
/// The <see cref="HawkDelegatingHandler"/> implementation that handles Hawk authentication for HTTP requests.
/// </summary>
public class InjectableHawkDelegatingHandler : HawkDelegatingHandler
{
    private readonly IOptionsMonitor<HawkSettings>? _optionsMonitor;

    /// <inheritdoc />
    public override HawkSettings Settings => _optionsMonitor?.CurrentValue ?? throw new NullReferenceException(nameof(_optionsMonitor.CurrentValue));

    /// <summary>
    /// Initializes a new instance of <see cref="HawkDelegatingHandler"/>.
    /// </summary>
    /// <param name="optionsMonitor">Used for notifications when <see cref="HawkSettings"/> instances change.</param>
    public InjectableHawkDelegatingHandler(IOptionsMonitor<HawkSettings> optionsMonitor)
    {
        _optionsMonitor = optionsMonitor;
    }
}
