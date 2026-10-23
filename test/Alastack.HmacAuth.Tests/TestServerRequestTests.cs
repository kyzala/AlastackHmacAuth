using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Alastack.HmacAuth.Tests;

/// <summary>
/// Validates how TestServer surfaces request parameters (scheme, host, port,
/// PathBase, content type). These tests pin the pipeline behavior that the
/// authentication handlers rely on when building the string to sign.
/// </summary>
public class TestServerRequestTests
{
    [Fact]
    public async Task Validate_RequestParameters_UsingNormalPort()
    {
        using var host = await CreateHostAsync();
        var server = host.GetTestServer();
        server.BaseAddress = new Uri("http://a.b.c/");
        var context = await server.SendAsync(c =>
        {
            c.Request.Method = HttpMethods.Get;
            c.Request.PathBase = "/api";
            c.Request.Path = "/Test";
            c.Request.QueryString = new QueryString("?id=1");
        });

        Assert.Equal(HttpProtocol.Http11, context.Request.Protocol);
        Assert.Equal("GET", context.Request.Method);
        Assert.Equal("http", context.Request.Scheme);
        Assert.Equal("a.b.c", context.Request.Host.Value);
        Assert.Equal("a.b.c", context.Request.Host.Host);
        Assert.Null(context.Request.Host.Port);
        Assert.Equal("/api", context.Request.PathBase.Value);
        Assert.Equal("/Test", context.Request.Path.Value);
        Assert.Equal("?id=1", context.Request.QueryString.Value);
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task Validate_RequestParameters_UsingSpecificPort()
    {
        using var host = await CreateHostAsync();
        var server = host.GetTestServer();
        server.BaseAddress = new Uri("https://a.b.c:5000/");
        var context = await server.SendAsync(c =>
        {
            c.Request.Method = HttpMethods.Get;
            c.Request.PathBase = "/api";
            c.Request.Path = "/Test";
            c.Request.QueryString = new QueryString("?id=1");
        });

        Assert.Equal("https", context.Request.Scheme);
        Assert.Equal("a.b.c:5000", context.Request.Host.Value);
        Assert.Equal(5000, context.Request.Host.Port);
        Assert.Equal("/api", context.Request.PathBase.Value);
        Assert.Equal("/Test", context.Request.Path.Value);
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task Validate_RequestParameters_WithPathBase()
    {
        using var host = await CreateHostAsync();
        var server = host.GetTestServer();
        server.BaseAddress = new Uri("https://a.b.c:5000/api/");
        var context = await server.SendAsync(c =>
        {
            c.Request.Protocol = "HTTP/2";
            c.Request.Method = HttpMethods.Get;
            c.Request.Path = "/Test";
            c.Request.QueryString = new QueryString("?id=1");
        });

        Assert.Equal(HttpProtocol.Http2, context.Request.Protocol);
        Assert.Equal("/api", context.Request.PathBase.Value);
        Assert.Equal("/Test", context.Request.Path.Value);
        Assert.Equal("?id=1", context.Request.QueryString.Value);
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task Validate_RequestParameters_WithoutPathBase()
    {
        using var host = await CreateHostAsync();
        var server = host.GetTestServer();
        server.BaseAddress = new Uri("https://a.b.c:5000/");
        var context = await server.SendAsync(c =>
        {
            c.Request.Method = HttpMethods.Get;
            c.Request.Path = "/api/Test";
            c.Request.QueryString = new QueryString("?id=1");
        });

        Assert.Equal("", context.Request.PathBase.Value);
        Assert.Equal("/api/Test", context.Request.Path.Value);
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task Validate_RequestParameters_WithContentType()
    {
        using var host = await CreateHostAsync();
        var server = host.GetTestServer();
        server.BaseAddress = new Uri("https://a.b.c:5000/api/");
        var context = await server.SendAsync(c =>
        {
            c.Request.ContentType = "application/json";
            c.Request.Method = HttpMethods.Post;
            c.Request.Path = "/Test";
        });

        Assert.Equal("POST", context.Request.Method);
        Assert.Equal("application/json", context.Request.ContentType);
        Assert.Equal("", context.Request.QueryString.Value);
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task Validate_RequestParameters_WithoutContentType()
    {
        using var host = await CreateHostAsync();
        var server = host.GetTestServer();
        server.BaseAddress = new Uri("https://a.b.c:5000/api/");
        var context = await server.SendAsync(c =>
        {
            c.Request.Method = HttpMethods.Post;
            c.Request.Path = "/Test";
        });

        Assert.Null(context.Request.ContentType);
        Assert.Equal(404, context.Response.StatusCode);
    }

    private static async Task<IHost> CreateHostAsync()
    {
        return await new HostBuilder()
            .ConfigureWebHost(webBuilder => webBuilder
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddAuthorization();
                })
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthorization();
                }))
            .StartAsync();
    }
}
