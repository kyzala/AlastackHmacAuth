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

public class HawkMiddlewareTests
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

    [Fact]
    public async Task Validate_RequestParameters_WithContentType()
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
            c.Request.ContentType = "application/json";
            c.Request.Method = HttpMethods.Post;
            c.Request.Path = "/Test";
            //c.Request.QueryString = new QueryString("?id=1");
        });

        Assert.True(context.RequestAborted.CanBeCanceled);
        Assert.Equal(HttpProtocol.Http11, context.Request.Protocol);
        Assert.Equal("POST", context.Request.Method);
        Assert.Equal("https", context.Request.Scheme);
        Assert.Equal("a.b.c:5000", context.Request.Host.Value);
        Assert.Equal("a.b.c", context.Request.Host.Host);
        Assert.Equal(5000, context.Request.Host.Port);
        Assert.Equal("/api", context.Request.PathBase.Value);
        Assert.Equal("/Test", context.Request.Path.Value);
        Assert.Equal("", context.Request.QueryString.Value);
        Assert.Equal("application/json", context.Request.ContentType);
        Assert.NotNull(context.Request.Body);
        Assert.NotNull(context.Request.Headers);
        Assert.NotNull(context.Response.Headers);
        Assert.NotNull(context.Response.Body);
        Assert.Equal(404, context.Response.StatusCode);
        Assert.Null(context.Features.Get<IHttpResponseFeature>()?.ReasonPhrase);
    }

    [Fact]
    public async Task Validate_RequestParameters_WithoutContentType()
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
            //c.Request.ContentType = "application/json";
            c.Request.Method = HttpMethods.Post;
            c.Request.Path = "/Test";
            //c.Request.QueryString = new QueryString("?id=1");
        });

        Assert.True(context.RequestAborted.CanBeCanceled);
        Assert.Equal(HttpProtocol.Http11, context.Request.Protocol);
        Assert.Equal("POST", context.Request.Method);
        Assert.Equal("https", context.Request.Scheme);
        Assert.Equal("a.b.c:5000", context.Request.Host.Value);
        Assert.Equal("a.b.c", context.Request.Host.Host);
        Assert.Equal(5000, context.Request.Host.Port);
        Assert.Equal("/api", context.Request.PathBase.Value);
        Assert.Equal("/Test", context.Request.Path.Value);
        Assert.Equal("", context.Request.QueryString.Value);
        Assert.Null(context.Request.ContentType);
        Assert.NotNull(context.Request.Body);
        Assert.NotNull(context.Request.Headers);
        Assert.NotNull(context.Response.Headers);
        Assert.NotNull(context.Response.Body);
        Assert.Equal(404, context.Response.StatusCode);
        Assert.Null(context.Features.Get<IHttpResponseFeature>()?.ReasonPhrase);
    }

    [Theory]
    [InlineData("Hawk id=\"id123\", ts=\"1662118565\", nonce=\"abcdef\", hash=\"MfdKig8i5ykUIFjQkiIfmdJ0eKx5nWatljTRy2hIYkc=\", mac=\"QMbhfMP+kUiixTSTSa9ALmc/bL4iT725p62/Dnck4mM=\"")]
    [InlineData("Hawk id=\"id123\", ts=\"1662118565\", nonce=\"abcdef\", hash=\"MfdKig8i5ykUIFjQkiIfmdJ0eKx5nWatljTRy2hIYkc=\", ext=\"extdata\", mac=\"kCVNXF0ki+2AcM8gf0BE3m7ShsvAghExAKjh2qMIjjc=\"")]
    [InlineData("Hawk id=\"id123\", ts=\"1662118565\", nonce=\"abcdef\", hash=\"MfdKig8i5ykUIFjQkiIfmdJ0eKx5nWatljTRy2hIYkc=\", ext=\"extdata\", mac=\"cNX1z5hywwV4Zeoejp81APyxPGvAst8zDbjy8uiK2f4=\", app=\"abc\", dlg=\"\"")]
    [InlineData("Hawk id=\"id123\", ts=\"1662118565\", nonce=\"abcdef\", hash=\"MfdKig8i5ykUIFjQkiIfmdJ0eKx5nWatljTRy2hIYkc=\", ext=\"extdata\", mac=\"O4MnqtWlnXVgS4QJNuVf2iB4XiV6uGlGIi0eU9eSrUA=\", app=\"abc\", dlg=\"123\"")]
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
        Assert.Equal("Hawk", context.User.Identity!.AuthenticationType);
        Assert.Equal("id123", context.User.Claims.FirstOrDefault()!.Value);
        Assert.False(context.Response.Headers.ContainsKey("Server-Authorization"));
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Theory]
    [InlineData("Hawk id=\"id123\", ts=\"1662118565\", nonce=\"abcdef\", mac=\"PrW3nCv0sln6lOEYEKiKFO0Xr9FrtT4lY7ZfgO+uK+4=\"")]
    [InlineData("Hawk id=\"id123\", ts=\"1662118565\", nonce=\"abcdef\", ext=\"extdata\", mac=\"jFFBjfNU18hdXCIeB/EQ+xe3ZhL0qF5ZsD+kjVMlxh0=\"")]
    [InlineData("Hawk id=\"id123\", ts=\"1662118565\", nonce=\"abcdef\", ext=\"extdata\", mac=\"QzHSDcM4mGppdrIKF5GAF/0vqJ05EC2Jw66R4C7rldg=\", app=\"abc\", dlg=\"\"")]
    [InlineData("Hawk id=\"id123\", ts=\"1662118565\", nonce=\"abcdef\", ext=\"extdata\", mac=\"ur1ZDiYXrFtrG80WS3WJI7Kz2aBl9egyD6ZEasQxCD8=\", app=\"abc\", dlg=\"123\"")]
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
        Assert.Equal("Hawk", context.User.Identity!.AuthenticationType);
        Assert.Equal("id123", context.User.Claims.FirstOrDefault()!.Value);
        Assert.False(context.Response.Headers.ContainsKey("Server-Authorization"));
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Theory]
    [InlineData(true, false, null, "Hawk mac=\"C++Uyj2bEBpwMR2+fftTPuK6BF/2PLWPVzmeLYwb+50=\"")]
    [InlineData(true, false, "", "Hawk mac=\"C++Uyj2bEBpwMR2+fftTPuK6BF/2PLWPVzmeLYwb+50=\", ext=\"\"")]
    [InlineData(true, false, "specific data", "Hawk mac=\"d0QZx/tYPxn2nu+zO/jRFHmWeOO4WGjE0d1s/M6SlX8=\", ext=\"specific data\"")]
    [InlineData(true, true, null, "Hawk mac=\"XTMIAieawkFMmVfj1ojf0Bc0aGRizoZHELQMKG8isEM=\", hash=\"NVuBm+XMyya3Tq4EhpZ0cQWjVUyIA8sKnySkKDOIM4M=\"")]
    [InlineData(true, true, "", "Hawk mac=\"XTMIAieawkFMmVfj1ojf0Bc0aGRizoZHELQMKG8isEM=\", hash=\"NVuBm+XMyya3Tq4EhpZ0cQWjVUyIA8sKnySkKDOIM4M=\", ext=\"\"")]
    [InlineData(true, true, "specific data", "Hawk mac=\"vGCbuG8FIYY5vXZsXfCll0n1W9JfvMjJwQezEy77w4s=\", hash=\"NVuBm+XMyya3Tq4EhpZ0cQWjVUyIA8sKnySkKDOIM4M=\", ext=\"specific data\"")]
    public async Task AddServerAuthorizationAsync_HawkMiddleware_ValidateServerAuthorizationHeader(bool enableServerAuthorization, bool includeResponsePayloadHash, string? ext, string expected)
    {
        var host = await new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                ConfigureWebHost(webBuilder, enableServerAuthorization, includeResponsePayloadHash, ext);
            })
            .StartAsync();

        var server = host.GetTestServer();
        server.BaseAddress = new Uri("http://a.b.c:5000/api/");
        var context = await server.SendAsync(c =>
        {
            c.Request.Headers.Authorization = "Hawk id=\"id123\", ts=\"1662118565\", nonce=\"abcdef\", hash=\"MfdKig8i5ykUIFjQkiIfmdJ0eKx5nWatljTRy2hIYkc=\", ext=\"extdata\", mac=\"kCVNXF0ki+2AcM8gf0BE3m7ShsvAghExAKjh2qMIjjc=\"";
            c.Request.ContentType = "application/json";
            c.Request.Method = HttpMethods.Post;
            c.Request.Path = "/data";
            c.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("{\"name\":\"value\"}"));
            c.Response.ContentType = "application/json";
            c.Response.Body = new MemoryStream(Encoding.UTF8.GetBytes("{\"result\":\"value\"}"));
        });

        Assert.True(context.User.Identity!.IsAuthenticated);
        Assert.Equal("Hawk", context.User.Identity!.AuthenticationType);
        Assert.Equal("id123", context.User.Claims.FirstOrDefault()!.Value);
        Assert.Equal(expected, context.Response.Headers["Server-Authorization"]);
        Assert.Equal(404, context.Response.StatusCode);
    }

    private static void ConfigureWebHost(IWebHostBuilder webBuilder, bool enableServerAuthorization = false, bool includeResponsePayloadHash = false, string? ext = null)
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
                    options.DefaultScheme = HawkDefaults.AuthenticationScheme;
                })
                .AddHawk(options =>
                {
                    var credential = new HawkCredential
                    {
                        AuthId = "id123",
                        AuthKey = "3@uo45er?",
                        EnableServerAuthorization = enableServerAuthorization,
                        IncludeResponsePayloadHash = includeResponsePayloadHash
                    };
                    options.EnableServerAuthorization = enableServerAuthorization;
                    options.IncludeResponsePayloadHash = includeResponsePayloadHash;
                    options.RequireTimeSkewValidation = false;
                    var dict = new Dictionary<string, HawkCredential> { { "id123", credential } };
                    options.CredentialProvider = new MemoryCredentialProvider<HawkCredential>(dict);
                    options.Events.OnSetSpecificData = context => { context.Data = ext; return Task.CompletedTask; };
                });
            })
            .Configure(app =>
            {
                app.UseRouting();
                app.UseAuthentication();
                app.UseHawkServerAuthorization();
                app.UseAuthorization();
            });
    }
}