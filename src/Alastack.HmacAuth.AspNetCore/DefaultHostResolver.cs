using Microsoft.AspNetCore.Http;

namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// The default implementation of <see cref="IHostResolver"/>.
/// Resolves the host from the leftmost <c>X-Forwarded-Host</c> entry, which is the host originally
/// used by the client, and falls back to <see cref="HttpRequest.Host"/> when the header is absent
/// or cannot be parsed. The ASP.NET Core Forwarded Headers Middleware is not required.
/// </summary>
public class DefaultHostResolver : IHostResolver
{
    /// <inheritdoc />
    public HostString Resolve(HttpRequest request)
    {
        var hosts = request.Headers["X-Forwarded-Host"]
            .ToString()
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (hosts.Length > 0)
        {
            var hostArray = hosts[0].Split(':');
            if (hostArray.Length == 2 && int.TryParse(hostArray[1], out var port))
            {
                return new HostString(hostArray[0], port);
            }

            if (hostArray.Length == 1)
            {
                var protos = request.Headers["X-Forwarded-Proto"]
                    .ToString()
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                var proto = protos.Length > 0 ? protos[0] : null;

                var fallbackPort = string.Equals(proto, "https", StringComparison.OrdinalIgnoreCase) ? 443
                    : string.Equals(proto, "http", StringComparison.OrdinalIgnoreCase) ? 80
                    : request.IsHttps ? 443 : 80;

                return new HostString(hostArray[0], fallbackPort);
            }

            // Unrecognized form (e.g. IPv6 literal or malformed port): fall back to Request.Host.
        }

        var currentPort = request.Host.Port ?? (request.IsHttps ? 443 : 80);
        return new HostString(request.Host.Host, currentPort);
    }
}
