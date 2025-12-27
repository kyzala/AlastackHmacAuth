using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// Middleware that adds Hawk server authorization.
/// </summary>
public class HawkMiddleware
{
    private readonly RequestDelegate _next;

    /// <summary>
    /// Initializes a new instance of <see cref="HawkMiddleware"/>.
    /// </summary>
    /// <param name="next">The next item in the middleware pipeline.</param>
    /// <exception cref="ArgumentNullException">If the next argument is <c>null</c>, an exception will be thrown.</exception>
    public HawkMiddleware(RequestDelegate next)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
    }
    /// <summary>
    /// Invokes the middleware performing authentication.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/>.</param>
    /// <param name="optionsMonitor">Used for notifications when <see cref="HawkOptions"/> instances change.</param>
    /// <returns>The task representing the asynchronous operation.</returns>
    public async Task Invoke(HttpContext context, IOptionsMonitor<HawkOptions> optionsMonitor)
    {
        var options = optionsMonitor.Get(HawkDefaults.AuthenticationScheme);
        if (options.EnableServerAuthorization)
        {
            var originalStream = context.Response.Body;
            try
            {
                using var memoryStream = new MemoryStream();
                context.Response.Body = memoryStream;
                await _next.Invoke(context);
                memoryStream.Position = 0;
                await AddServerAuthorizationAsync(context, options);
                await memoryStream.CopyToAsync(originalStream);
            }
            finally
            {
                context.Response.Body = originalStream;
            }
        }
        else
        {
            await _next(context);
        }
    }

    private async Task AddServerAuthorizationAsync(HttpContext context, HawkOptions options)
    {
        if (!context.Items.TryGetValue("hawk:credential", out var val1) || !context.Items.TryGetValue("hawk:hawkData", out var val2))
        {
            return;
        }
        var credential = (HawkCredential)val1!;
        var macParameters = (HawkData)val2!;
        macParameters.Hash = null;
        macParameters.Ext = null;
        var crypto = options.CryptoFactory.Create(credential.HmacAlgorithm, credential.HashAlgorithm, credential.AuthKey);

        if (options.IncludeResponsePayloadHash && credential.IncludeResponsePayloadHash)
        {
            var stream = context.Response.Body as MemoryStream;
            var contentType = context.Response.ContentType?.Split(';')[0];
            macParameters.Hash = crypto.CalculatePayloadHash(stream!.ToArray(), contentType);
        }
        var sdContext = new HawkSpecificDataContext(context, options, credential);
        await options.Events.SetSpecificData(sdContext);
        macParameters.Ext = sdContext.Data;
        var mac = crypto.CalculateResponseMac(macParameters);

        var hash = macParameters.Hash == null ? String.Empty : $", hash=\"{macParameters.Hash}\"";
        var ext = macParameters.Ext == null ? String.Empty : $", ext=\"{macParameters.Ext}\"";
        var wwwAuthenticate = $"{HawkDefaults.AuthenticationScheme} mac=\"{mac}\"{hash}{ext}";
        context.Response.Headers["Server-Authorization"] = wwwAuthenticate;
    }
}