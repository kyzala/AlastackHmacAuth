using Microsoft.AspNetCore.Http;

namespace Alastack.HmacAuth.AspNetCore;

/*
 * X-Forwarded-For: ::ffff:192.168.1.102, ::ffff:192.168.1.103, ::ffff:192.168.1.102, ::ffff:192.168.1.103, ::ffff:192.168.1.102
 * X-Forwarded-Host: 192.168.1.103, 192.168.1.102:1080, 192.168.1.103:2080, 192.168.1.102:2080, 192.168.1.103:3080
 * X-Forwarded-Proto: http, http, http, http, http
 */

/// <summary>
/// The default implementation of <see cref="IHostResolver"/>.
/// </summary>
public class DefaultHostResolver : IHostResolver
{
    /// <inheritdoc />
    public HostString Resolve(HttpRequest request, int forwardIndex)
    {
        if (request.Headers.TryGetValue("X-Forwarded-Host", out var xForwardedHost))
        {
            var hostsArray = xForwardedHost.First()?.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            if (hostsArray is not null && hostsArray.Length > 0)
            {
                var hostArray = hostsArray[^(forwardIndex + 1)].Split(':');
                if (hostArray.Length == 2)
                {
                    return new HostString(hostArray[0], Int32.Parse(hostArray[1]));
                }
                if (request.Headers.TryGetValue("X-Forwarded-Proto", out var xForwardedProto))
                {
                    var protosArray = xForwardedProto.First()?.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    if (protosArray is not null && protosArray.Length > 0)
                    {
                        var proto = protosArray[^(forwardIndex + 1)];
                        var port = proto.Equals("https", StringComparison.OrdinalIgnoreCase) ? 443 : 80;
                        return new HostString(hostArray[0], port);
                    }
                }
                return new HostString(hostArray[0], 443);
            }
        }
        var port1 = request.Host.Port ?? (request.IsHttps ? 443 : 80);
        return new HostString(request.Host.Host, port1);
    }
}