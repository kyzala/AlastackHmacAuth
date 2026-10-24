using Alastack.HmacAuth.Options;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Refit;
using Sample.Common;

namespace ClientRefitSample;

internal class Program
{
    // Default addresses route through the ApiProxy sample chain.
    private const string DefaultHmacAddress = "https://localhost:1080/";
    private const string DefaultHawkAddress = "http://192.168.1.102:2080/";

    static async Task Main(string[] args)
    {
        var schemeIndex = ConsoleMenu.Pick("Authentication scheme", new[] { "Hmac", "Hawk" });
        var useHmac = schemeIndex == 0;
        var defaultAddress = useHmac ? DefaultHmacAddress : DefaultHawkAddress;
        var baseAddress = new Uri(ConsoleMenu.ReadString("Base address", defaultAddress));

        using var host = CreateHost(useHmac, baseAddress);
        var apiClient = host.Services.GetRequiredService<IApiClient>();

        await ConsoleMenu.RunAsync("TodoItems API (Refit)", new ConsoleMenu.Item[]
        {
            new("GET /debug-forwarded", async () => Console.WriteLine(await apiClient.DebugForwardedAsync())),
            new("List all items", async () => TodoItemConsole.Print(await apiClient.GetTodoItemsAsync())),
            new("Get item by id", async () =>
            {
                var id = ConsoleMenu.ReadLong("Id", 1);
                TodoItemConsole.Print(await apiClient.GetTodoItemAsync(id));
            }),
            new("Create item", async () =>
            {
                var name = ConsoleMenu.ReadString("Name", "walk dog");
                await apiClient.CreateTodoItemAsync(new TodoItem { Name = name, IsComplete = false });
                Console.WriteLine("Created.");
            }),
            new("Update item", async () =>
            {
                var id = ConsoleMenu.ReadLong("Id", 1);
                var name = ConsoleMenu.ReadString("Name", "feed fish");
                await apiClient.UpdateTodoItemAsync(new TodoItem { Id = id, Name = name, IsComplete = true });
                Console.WriteLine("Updated.");
            }),
            new("Delete item", async () =>
            {
                var id = ConsoleMenu.ReadLong("Id", 1);
                await apiClient.DeleteTodoItemAsync(id);
                Console.WriteLine("Deleted.");
            }),
        });
    }

    static IHost CreateHost(bool useHmac, Uri baseAddress)
    {
        return new HostBuilder()
            .ConfigureServices(services =>
            {
                if (useHmac)
                {
                    services.AddSampleHmacAuth();
                }
                else
                {
                    services.AddSampleHawkAuth();
                }

                var httpClientBuilder = services.AddRefitClient<IApiClient>()
                    .ConfigureHttpClient(httpClient =>
                    {
                        httpClient.BaseAddress = baseAddress;
                        httpClient.DefaultRequestVersion = new Version(2, 0);
                    });
                if (useHmac)
                {
                    httpClientBuilder.AddHttpMessageHandler<DefaultHmacDelegatingHandler>();
                }
                else
                {
                    httpClientBuilder.AddHttpMessageHandler<InjectableHawkDelegatingHandler>();
                }
            })
            .Build();
    }
}
