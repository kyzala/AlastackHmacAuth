using Alastack.HmacAuth.AspNetCore;
using Microsoft.AspNetCore.Http;

namespace Alastack.HmacAuth.Tests;

public class DefaultHostResolverTests
{
    private static DefaultHttpContext CreateContext(string scheme = "http", string host = "example.com", int? port = null)
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = scheme;
        context.Request.Host = port.HasValue ? new HostString(host, port.Value) : new HostString(host);
        return context;
    }

    [Fact]
    public void Resolve_NoForwardedHeader_HttpWithoutPort_DefaultsTo80()
    {
        var context = CreateContext("http", "example.com");
        var result = new DefaultHostResolver().Resolve(context.Request);
        Assert.Equal("example.com", result.Host);
        Assert.Equal(80, result.Port);
    }

    [Fact]
    public void Resolve_NoForwardedHeader_HttpsWithoutPort_DefaultsTo443()
    {
        var context = CreateContext("https", "example.com");
        var result = new DefaultHostResolver().Resolve(context.Request);
        Assert.Equal("example.com", result.Host);
        Assert.Equal(443, result.Port);
    }

    [Fact]
    public void Resolve_NoForwardedHeader_ExplicitPort_UsesRequestPort()
    {
        var context = CreateContext("https", "example.com", 5000);
        var result = new DefaultHostResolver().Resolve(context.Request);
        Assert.Equal("example.com", result.Host);
        Assert.Equal(5000, result.Port);
    }

    [Fact]
    public void Resolve_ForwardedHostWithPort_UsesLeftmostEntry()
    {
        var context = CreateContext("http", "internal:5000");
        context.Request.Headers["X-Forwarded-Host"] = "client.example.com:8080, proxy1:2080, proxy2:3080";
        var result = new DefaultHostResolver().Resolve(context.Request);
        Assert.Equal("client.example.com", result.Host);
        Assert.Equal(8080, result.Port);
    }

    [Fact]
    public void Resolve_ForwardedHostWithSpaces_TrimsEntries()
    {
        var context = CreateContext();
        context.Request.Headers["X-Forwarded-Host"] = " client.example.com:10443 , proxy1:2080";
        var result = new DefaultHostResolver().Resolve(context.Request);
        Assert.Equal("client.example.com", result.Host);
        Assert.Equal(10443, result.Port);
    }

    [Fact]
    public void Resolve_ForwardedHostWithoutPort_HttpsProto_DefaultsTo443()
    {
        var context = CreateContext();
        context.Request.Headers["X-Forwarded-Host"] = "client.example.com, proxy1:2080";
        context.Request.Headers["X-Forwarded-Proto"] = "https, http";
        var result = new DefaultHostResolver().Resolve(context.Request);
        Assert.Equal("client.example.com", result.Host);
        Assert.Equal(443, result.Port);
    }

    [Fact]
    public void Resolve_ForwardedHostWithoutPort_HttpProto_DefaultsTo80()
    {
        var context = CreateContext();
        context.Request.Headers["X-Forwarded-Host"] = "client.example.com";
        context.Request.Headers["X-Forwarded-Proto"] = "http";
        var result = new DefaultHostResolver().Resolve(context.Request);
        Assert.Equal(80, result.Port);
    }

    [Fact]
    public void Resolve_ForwardedHostWithoutPort_NoProto_FallsBackToRequestScheme()
    {
        var context = CreateContext("https", "internal:5000");
        context.Request.Headers["X-Forwarded-Host"] = "client.example.com";
        var result = new DefaultHostResolver().Resolve(context.Request);
        Assert.Equal("client.example.com", result.Host);
        Assert.Equal(443, result.Port);
    }

    [Theory]
    [InlineData("client.example.com:abc")]   // non-numeric port
    [InlineData("client.example.com:99999")] // port out of range
    [InlineData("client.example.com:-1")]    // negative port
    [InlineData("[::1]:8080")]               // IPv6 literal (unsupported form)
    public void Resolve_MalformedForwardedHost_FallsBackToRequestHost(string forwardedHost)
    {
        var context = CreateContext("https", "internal.example.com", 5000);
        context.Request.Headers["X-Forwarded-Host"] = forwardedHost;
        var result = new DefaultHostResolver().Resolve(context.Request);
        Assert.Equal("internal.example.com", result.Host);
        Assert.Equal(5000, result.Port);
    }

    [Fact]
    public void Resolve_EmptyForwardedHost_FallsBackToRequestHost()
    {
        var context = CreateContext("http", "internal.example.com", 5000);
        context.Request.Headers["X-Forwarded-Host"] = "";
        var result = new DefaultHostResolver().Resolve(context.Request);
        Assert.Equal("internal.example.com", result.Host);
        Assert.Equal(5000, result.Port);
    }
}
