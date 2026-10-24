using Refit;
using Sample.Common;

namespace ClientRefitSample;

public interface IApiClient
{
    [Get("/api/TodoItems")]
    Task<IEnumerable<TodoItem>?> GetTodoItemsAsync();

    [Get("/api/TodoItems/{id}")]
    Task<TodoItem?> GetTodoItemAsync(long id);

    [Post("/api/TodoItems")]
    Task CreateTodoItemAsync(TodoItem todoItem);

    [Put("/api/TodoItems/{todoItem.id}")]
    Task UpdateTodoItemAsync(TodoItem todoItem);

    [Delete("/api/TodoItems/{id}")]
    Task DeleteTodoItemAsync(long id);

    [Get("/debug-forwarded")]
    Task<object> DebugForwardedAsync();
}