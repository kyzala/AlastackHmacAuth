using Sample.Common;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using static System.Net.Mime.MediaTypeNames;

namespace ClientHostSample;

public sealed class ApiClient
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    private readonly HttpClient _httpClient;

    public ApiClient(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<IEnumerable<TodoItem>?> GetTodoItemsAsync()
    {
        return await _httpClient.GetFromJsonAsync<IEnumerable<TodoItem>>("/api/TodoItems", JsonOptions);
    }

    public async Task<TodoItem?> GetTodoItemAsync(long id)
    {
        return await _httpClient.GetFromJsonAsync<TodoItem>($"/api/TodoItems/{id}", JsonOptions);
    }

    public async Task CreateTodoItemAsync(TodoItem todoItem)
    {
        var content = new StringContent(JsonSerializer.Serialize(todoItem), Encoding.UTF8, Application.Json);
        using var response = await _httpClient.PostAsync("/api/TodoItems", content);
        response.EnsureSuccessStatusCode();
    }

    public async Task UpdateTodoItemAsync(TodoItem todoItem)
    {
        var content = new StringContent(JsonSerializer.Serialize(todoItem), Encoding.UTF8, Application.Json);
        using var response = await _httpClient.PutAsync($"/api/TodoItems/{todoItem.Id}", content);
        response.EnsureSuccessStatusCode();
    }

    public async Task DeleteTodoItemAsync(long id)
    {
        using var response = await _httpClient.DeleteAsync($"/api/TodoItems/{id}");
        response.EnsureSuccessStatusCode();
    }
}
