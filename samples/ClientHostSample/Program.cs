using Alastack.HmacAuth;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Sample.Common;

namespace ClientHostSample
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            var host1 = CreateHmacAuthenticationHost(new Uri("https://localhost:5001/"));
            var apiClient1 = host1.Services.GetRequiredService<ApiClient>();
            await ApiInvoke(apiClient1);

            var host2 = CreateHawkAuthenticationHost(new Uri("https://localhost:5001/"));
            var apiClient2 = host2.Services.GetRequiredService<ApiClient>();
            await ApiInvoke(apiClient2);

            Console.ReadKey();
        }

        static IHost CreateHmacAuthenticationHost(Uri serverAddress)
        {
            return new HostBuilder()
                .ConfigureServices(services =>
                {
                    services.Configure<HmacSettings>(options =>
                    {
                        options.AppId = "id123";
                        options.AppKey = "3@uo45er?";
                    });
                    services.AddSingleton<IValidateOptions<HmacSettings>, Sample.Common.HmacConfigValidation>();
                    services.AddTransient<HmacDelegatingHandler>();
                    services.AddHttpClient<ApiClient>("ApiClient", httpClient =>
                    {
                        httpClient.BaseAddress = serverAddress;
                        httpClient.DefaultRequestVersion = new Version(2, 0);
                    })
                    .AddHttpMessageHandler<HmacDelegatingHandler>();
                })
                .Build();
        }

        static IHost CreateHawkAuthenticationHost(Uri serverAddress)
        {
            return new HostBuilder()
                .ConfigureServices(services =>
                {
                    services.Configure<HawkSettings>(options =>
                    {
                        options.AuthId = "id123";
                        options.AuthKey = "3@uo45er?";
                        options.App = "app";
                        options.Dlg = "dlg";
                        options.EnableServerAuthorizationValidation = true;
                        options.GetSpecificData = async (request, options) => await Task.FromResult("some-data");
                    });
                    services.AddSingleton<IValidateOptions<HawkSettings>, Sample.Common.HawkConfigValidation>();
                    services.AddTransient<HawkDelegatingHandler>();
                    services.AddHttpClient<ApiClient>("ApiClient", httpClient =>
                    {
                        httpClient.BaseAddress = serverAddress;
                        httpClient.DefaultRequestVersion = new Version(2, 0);
                    })
                    .AddHttpMessageHandler<HawkDelegatingHandler>();
                })
                .Build();
        }

        static async Task ApiInvoke(ApiClient apiClient)
        {
            await apiClient.CreateTodoItemAsync(new TodoItem { Name = "walk dog", IsComplete = true });
            await apiClient.UpdateTodoItemAsync(new TodoItem { Id = 1, Name = "feed fish", IsComplete = true });
            Print(await apiClient.GetTodoItemsAsync());
            Print(await apiClient.GetTodoItemAsync(1));
            await apiClient.DeleteTodoItemAsync(1);
        }

        static void Print(IEnumerable<TodoItem>? items)
        {
            if (items != null)
            {
                foreach (var item in items)
                {
                    Print(item);
                }
            }
        }

        static void Print(TodoItem? item)
        {
            if (item != null)
            {
                Console.WriteLine($"{item.Id}\t{item.Name}\t{item.IsComplete}");
            }
        }
    }
}