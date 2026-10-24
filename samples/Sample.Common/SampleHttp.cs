using System.Net.Security;

namespace Sample.Common;

public static class SampleHttp
{
    /// <summary>
    /// Development-only HTTP handler: accepts the self-signed dev certificate used by the samples.
    /// </summary>
    public static SocketsHttpHandler CreateDevHandler() => new()
    {
        ConnectTimeout = TimeSpan.FromSeconds(10),
        PooledConnectionLifetime = TimeSpan.FromSeconds(1000),
        SslOptions = new SslClientAuthenticationOptions
        {
            RemoteCertificateValidationCallback = (_, _, _, _) => true
        },
        UseCookies = false
    };
}
