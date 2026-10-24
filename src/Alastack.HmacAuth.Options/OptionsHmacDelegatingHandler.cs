using Alastack.HmacAuth;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Text;

namespace Alastack.HmacAuth.Options;

/// <summary>
/// The <see cref="HmacDelegatingHandler"/> implementation that handles Hmac authentication for HTTP requests.
/// </summary>
public class OptionsHmacDelegatingHandler : HmacDelegatingHandler
{
    private readonly IOptionsMonitor<HmacSettings>? _optionsMonitor;

    /// <inheritdoc />
    public override HmacSettings Settings => _optionsMonitor?.CurrentValue ?? throw new NullReferenceException(nameof(_optionsMonitor.CurrentValue));

    /// <summary>
    /// Initializes a new instance of <see cref="HawkDelegatingHandler"/>.
    /// </summary>
    /// <param name="optionsMonitor">Used for notifications when <see cref="HmacSettings"/> instances change.</param>
    public OptionsHmacDelegatingHandler(IOptionsMonitor<HmacSettings> optionsMonitor)
    {
        _optionsMonitor = optionsMonitor;
    }
}
