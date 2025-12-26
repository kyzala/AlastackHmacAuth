using Alastack.HmacAuth;
using Alastack.HmacAuth.AspNetCore;
using Alastack.HmacAuth.Credentials;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Text;

namespace Alastack.HmacAuth.Tests;

public class MiddlewareTests
{
    [Fact]
    public async Task Validate_RequestParameters_UsingNormalPort()
    {
        using var host = await new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                ConfigureWebHost(webBuilder);
            })
            .StartAsync();

        var server = host.GetTestServer();
        server.BaseAddress = new Uri("http://a.b.c/");
        var context = await server.SendAsync(c =>
        {
            c.Request.Method = HttpMethods.Get;
            c.Request.PathBase = "/api";
            c.Request.Path = "/Test";
            c.Request.QueryString = new QueryString("?id=1");
        });

        Assert.True(context.RequestAborted.CanBeCanceled);
        Assert.Equal(HttpProtocol.Http11, context.Request.Protocol);
        Assert.Equal("GET", context.Request.Method);
        Assert.Equal("http", context.Request.Scheme);
        Assert.Equal("a.b.c", context.Request.Host.Value);
        Assert.Equal("a.b.c", context.Request.Host.Host);
        Assert.Null(context.Request.Host.Port);
        Assert.Equal("/api", context.Request.PathBase.Value);
        Assert.Equal("/Test", context.Request.Path.Value);
        Assert.Equal("?id=1", context.Request.QueryString.Value);
        Assert.NotNull(context.Request.Body);
        Assert.NotNull(context.Request.Headers);
        Assert.NotNull(context.Response.Headers);
        Assert.NotNull(context.Response.Body);
        Assert.Equal(404, context.Response.StatusCode);
        Assert.Null(context.Features.Get<IHttpResponseFeature>()?.ReasonPhrase);
    }

    [Fact]
    public async Task Validate_RequestParameters_UsingSpecificPort()
    {
        using var host = await new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                ConfigureWebHost(webBuilder);
            })
            .StartAsync();

        var server = host.GetTestServer();
        server.BaseAddress = new Uri("https://a.b.c:5000/");
        var context = await server.SendAsync(c =>
        {
            c.Request.Protocol = "HTTP/1.1";
            c.Request.Method = HttpMethods.Get;
            c.Request.PathBase = "/api";
            c.Request.Path = "/Test";
            c.Request.QueryString = new QueryString("?id=1");
        });

        Assert.True(context.RequestAborted.CanBeCanceled);
        Assert.Equal(HttpProtocol.Http11, context.Request.Protocol);
        Assert.Equal("GET", context.Request.Method);
        Assert.Equal("https", context.Request.Scheme);
        Assert.Equal("a.b.c:5000", context.Request.Host.Value);
        Assert.Equal("a.b.c", context.Request.Host.Host);
        Assert.Equal(5000, context.Request.Host.Port);
        Assert.Equal("/api", context.Request.PathBase.Value);
        Assert.Equal("/Test", context.Request.Path.Value);
        Assert.Equal("?id=1", context.Request.QueryString.Value);
        Assert.NotNull(context.Request.Body);
        Assert.NotNull(context.Request.Headers);
        Assert.NotNull(context.Response.Headers);
        Assert.NotNull(context.Response.Body);
        Assert.Equal(404, context.Response.StatusCode);
        Assert.Null(context.Features.Get<IHttpResponseFeature>()?.ReasonPhrase);
    }

    [Fact]
    public async Task Validate_RequestParameters_WithPathBase()
    {
        using var host = await new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                ConfigureWebHost(webBuilder);
            })
            .StartAsync();

        var server = host.GetTestServer();
        server.BaseAddress = new Uri("https://a.b.c:5000/api/");
        var context = await server.SendAsync(c =>
        {
            c.Request.Protocol = "HTTP/2";
            c.Request.Method = HttpMethods.Get;
            c.Request.Path = "/Test";
            c.Request.QueryString = new QueryString("?id=1");
        });

        Assert.True(context.RequestAborted.CanBeCanceled);
        Assert.Equal(HttpProtocol.Http2, context.Request.Protocol);
        Assert.Equal("GET", context.Request.Method);
        Assert.Equal("https", context.Request.Scheme);
        Assert.Equal("a.b.c:5000", context.Request.Host.Value);
        Assert.Equal("a.b.c", context.Request.Host.Host);
        Assert.Equal(5000, context.Request.Host.Port);
        Assert.Equal("/api", context.Request.PathBase.Value);
        Assert.Equal("/Test", context.Request.Path.Value);
        Assert.Equal("?id=1", context.Request.QueryString.Value);
        Assert.NotNull(context.Request.Body);
        Assert.NotNull(context.Request.Headers);
        Assert.NotNull(context.Response.Headers);
        Assert.NotNull(context.Response.Body);
        Assert.Equal(404, context.Response.StatusCode);
        Assert.Null(context.Features.Get<IHttpResponseFeature>()?.ReasonPhrase);
    }

    [Fact]
    public async Task Validate_RequestParameters_WithoutPathBase()
    {
        using var host = await new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                ConfigureWebHost(webBuilder);
            })
            .StartAsync();

        var server = host.GetTestServer();
        server.BaseAddress = new Uri("https://a.b.c:5000/");
        var context = await server.SendAsync(c =>
        {
            c.Request.Method = HttpMethods.Get;
            c.Request.Path = "/api/Test";
            c.Request.QueryString = new QueryString("?id=1");
        });

        Assert.True(context.RequestAborted.CanBeCanceled);
        Assert.Equal(HttpProtocol.Http11, context.Request.Protocol);
        Assert.Equal("GET", context.Request.Method);
        Assert.Equal("https", context.Request.Scheme);
        Assert.Equal("a.b.c:5000", context.Request.Host.Value);
        Assert.Equal("a.b.c", context.Request.Host.Host);
        Assert.Equal(5000, context.Request.Host.Port);
        Assert.Equal("", context.Request.PathBase.Value);
        Assert.Equal("/api/Test", context.Request.Path.Value);
        Assert.Equal("?id=1", context.Request.QueryString.Value);
        Assert.NotNull(context.Request.Body);
        Assert.NotNull(context.Request.Headers);
        Assert.NotNull(context.Response.Headers);
        Assert.NotNull(context.Response.Body);
        Assert.Equal(404, context.Response.StatusCode);
        Assert.Null(context.Features.Get<IHttpResponseFeature>()?.ReasonPhrase);
    }

    [Theory]
    [InlineData("Hmac id123:1662118565:abcdef:fDsO2Fhqs4wlQbdlQEUiz0zkv+257n1SwN76jDjy7lk=:megVFcCd4uYcboNPG8BqzQ==")]
    public async Task HandleAuthenticateAsync_HawkHandler_ValidateIncludePayloadHash(string authHeaderValue)
    {
        var host = await new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                ConfigureWebHost(webBuilder);
            })
            .StartAsync();

        var server = host.GetTestServer();
        server.BaseAddress = new Uri("http://a.b.c:5000/api/");
        var context = await server.SendAsync(c =>
        {
            c.Request.Headers.Authorization = authHeaderValue;
            c.Request.ContentType = "application/json";
            c.Request.Method = HttpMethods.Post;
            c.Request.Path = "/data";
            c.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("{\"name\":\"value\"}"));
            c.Response.ContentType = "application/json";
            c.Response.Body = new MemoryStream(Encoding.UTF8.GetBytes("{\"result\":\"value\"}"));
        });

        Assert.True(context.User.Identity!.IsAuthenticated);
        Assert.Equal("Hmac", context.User.Identity!.AuthenticationType);
        Assert.Equal("id123", context.User.Claims.FirstOrDefault()!.Value);
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Theory]
    [InlineData("Hmac id123:1662118565:abcdef:3ru7ibxtMinMNvfDTm9R+b86gKg7rn20DfzUOkCOgpA=:")]
    public async Task HandleAuthenticateAsync_HawkHandler__ValidateExcludePayloadHash(string authHeaderValue)
    {
        using var host = await new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                ConfigureWebHost(webBuilder);
            })
            .StartAsync();

        var server = host.GetTestServer();
        server.BaseAddress = new Uri("http://a.b.c:5000/api/");
        var context = await server.SendAsync(c =>
        {
            c.Request.Headers.Authorization = authHeaderValue;
            //c.Request.ContentType = "application/json";
            c.Request.Method = HttpMethods.Get;
            c.Request.Path = "/q";
            c.Request.QueryString = new QueryString("?a=1&b=2");
        });

        Assert.True(context.User.Identity!.IsAuthenticated);
        Assert.Equal("Hmac", context.User.Identity!.AuthenticationType);
        Assert.Equal("id123", context.User.Claims.FirstOrDefault()!.Value);
        Assert.Equal(404, context.Response.StatusCode);
    }

    private static void ConfigureWebHost(IWebHostBuilder webBuilder)
    {
        webBuilder
            .UseTestServer()
            .ConfigureServices(services =>
            {
                services.AddMemoryCache();
                services.AddRouting();
                services.AddAuthentication();
                services.AddAuthorization();
                services.AddAuthentication(options =>
                {
                    options.DefaultScheme = HmacDefaults.AuthenticationScheme;
                })
                .AddHmac(options =>
                {
                    var credential = new HmacCredential
                    {
                        AppId = "id123",
                        AppKey = "3@uo45er?"
                    };
                    options.RequireTimeSkewValidation = false;
                    var dict = new Dictionary<string, HmacCredential> { { "id123", credential } };
                    options.CredentialProvider = new MemoryCredentialProvider<HmacCredential>(dict);
                });
            })
            .Configure(app =>
            {
                app.UseRouting();
                app.UseAuthentication();
                app.UseAuthorization();
            });
    }
}