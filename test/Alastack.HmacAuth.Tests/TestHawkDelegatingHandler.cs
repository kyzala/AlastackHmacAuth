using System.Net;
using System.Net.Http.Headers;
using System.Text;
using static System.Net.Mime.MediaTypeNames;

namespace Alastack.HmacAuth.Tests;

public class TestHawkDelegatingHandler : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"name\":\"value\"}", Encoding.UTF8, Application.Json)
        };
        if (request.Method == HttpMethod.Post)
        {
            response.Headers.Add("Server-Authorization", "Hawk mac=\"+pqdXC3Mq8yNc9PBF8KemEykJM8171m5Z6nvI2OxUBM=\", hash=\"MfdKig8i5ykUIFjQkiIfmdJ0eKx5nWatljTRy2hIYkc=\", ext=\"extdata\"");
        }
        if (request.Method == HttpMethod.Put)
        {
            response.Headers.Add("Server-Authorization", "Hawk mac=\"+pqdXC3Mq8yNc9PBF8KemEykJM8171m5Z6nvI2OxUBM=\", hash=\"abcdef\", ext=\"extdata\"");
        }
        if (request.Method == HttpMethod.Delete)
        {
            //"Hawk ts=\"1662118566\", tsm=\"uq6KsegL6N6hYoG131A++XyWZvmKN1BxBNHJ70GYuOA=\", error=\"Stale timestamp.\"";
            response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("Hawk", "ts=\"1662118566\", tsm=\"abcdef\", error=\"Stale timestamp.\""));
            response.StatusCode = HttpStatusCode.Unauthorized;
        }
        return await Task.FromResult(response);
    }
}