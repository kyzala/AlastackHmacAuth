using System.Runtime.Serialization;

namespace Alastack.HmacAuth;

/// <summary>
/// The exception that is thrown when server timestamp validation fails in Hawk authentication
/// </summary>
[Serializable]
public class HawkTimestampException : Exception
{
    /// <summary>
    /// Gets the server timestamp that failed validation
    /// </summary>
    public long Timestamp { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="HawkTimestampException"/> class
    /// </summary>
    /// <param name="message">The error message that explains the reason for the exception</param>
    /// <param name="timestamp">The server timestamp that failed validation</param>
    public HawkTimestampException(string message, long timestamp)
        : base(message)
    {
        Timestamp = timestamp;
    }
}