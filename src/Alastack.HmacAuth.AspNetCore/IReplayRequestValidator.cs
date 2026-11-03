namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// An HTTP replay request validator abstraction.
/// </summary>
public interface IReplayRequestValidator
{
    /// <summary>
    /// HTTP Replay Request Validation.
    /// </summary>
    /// <param name="id">HTTP request id.</param>
    /// <param name="nonce">A nonce string.</param>
    /// <param name="timestamp">HTTP request timestamp.</param>
    /// <param name="maxReplayRequestAge">The maximum value(seconds) of the replay request age.</param>
    /// <param name="cancellationToken">Optional. A <see cref="CancellationToken" /> to cancel the operation.</param>
    /// <returns>The task object representing the asynchronous operation.</returns>
    Task<bool> ValidateAsync(string id, string nonce, long timestamp, long maxReplayRequestAge, CancellationToken cancellationToken = default);
}
