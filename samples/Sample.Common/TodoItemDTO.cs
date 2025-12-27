namespace Sample.Common;

/// <summary>
/// TodoItemDTO
/// </summary>
public class TodoItemDTO
{
    /// <summary>
    /// Id
    /// </summary>
    public long Id { get; set; }

    /// <summary>
    /// Name
    /// </summary>
    public string? Name { get; set; }

    /// <summary>
    /// IsComplete
    /// </summary>
    public bool IsComplete { get; set; }
}