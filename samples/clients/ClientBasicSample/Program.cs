using Alastack.HmacAuth;
using System.Net.Http;
using System.Net.Security;

Console.WriteLine(Environment.Version);

string appId = "id123";
string appKey = "3@uo45er?";

Console.WriteLine("\n=> Test hmac auth ...\n");
var hmacHandler = new HmacDelegatingHandler(appId, appKey);
await ApiInvoke(hmacHandler);

Console.WriteLine("\n=> Test hawk auth ...\n");
var hawkHandler = new HawkDelegatingHandler(appId, appKey);
await ApiInvoke(hawkHandler);

Console.WriteLine("\n=> Test completed\n");
Console.ReadKey();


static async Task ApiInvoke(DelegatingHandler authHandler)
{
    // Create an SocketsHttpHandler object
    using var handler = new SocketsHttpHandler
    {
        ConnectTimeout = TimeSpan.FromSeconds(10),
        PooledConnectionLifetime = TimeSpan.FromSeconds(1000),
        SslOptions = new SslClientAuthenticationOptions()
        {
            RemoteCertificateValidationCallback = (sender, certificate, chain, errors) => true
        },
        UseCookies = false
    };

    authHandler.InnerHandler = handler;    

    // Create an HttpClient object
    using var client = new HttpClient(authHandler, disposeHandler: false)
    {
        BaseAddress = new Uri("https://localhost:5001/")
    };

    // Call asynchronous network methods in a try/catch block to handle exceptions
    try
    {
        var response = await client.GetAsync("/WeatherForecast");
        response.EnsureSuccessStatusCode();
        string responseBody = await response.Content.ReadAsStringAsync();
        Console.WriteLine(responseBody);

        Parallel.For(1, 100, index =>
        {
            var response = client.GetAsync("/WeatherForecast").Result;
            response.EnsureSuccessStatusCode();
            string responseBody = response.Content.ReadAsStringAsync().Result;
            Console.WriteLine($"{index}: {responseBody}");
        }
        );
    }
    catch (HttpRequestException e)
    {
        Console.WriteLine("\nException Caught!");
        Console.WriteLine("Message :{0} ", e.Message);
    }
}