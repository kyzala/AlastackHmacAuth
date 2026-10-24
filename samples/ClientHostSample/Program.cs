using Alastack.HmacAuth.Options;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Sample.Common;

namespace ClientHostSample;

internal class Program
{
    static async Task Main(string[] args)
    {
        var schemeIndex = ConsoleMenu.Pick("Authentication scheme", new[] { "Hmac", "Hawk" });
        var baseAddress = new Uri(ConsoleMenu.ReadString("Base address", SampleCredentials.DefaultBaseAddress));

        using var host = CreateHost(schemeIndex == 0, baseAddress);
        var apiClient = host.Services.GetRequiredService<ApiClient>();

        await ConsoleMenu.RunAsync("TodoItems API", new ConsoleMenu.Item[]
        {
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

                var httpClientBuilder = services.AddHttpClient<ApiClient>("ApiClient", httpClient =>
                {
                    httpClient.BaseAddress = baseAddress;
                    httpClient.DefaultRequestVersion = new Version(2, 0);
                });
                if (useHmac)
                {
                    httpClientBuilder.AddHttpMessageHandler<OptionsHmacDelegatingHandler>();
                }
                else
                {
                    httpClientBuilder.AddHttpMessageHandler<OptionsHawkDelegatingHandler>();
                }
            })
            .Build();
    }
}
