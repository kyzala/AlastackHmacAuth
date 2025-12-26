using System.Runtime.Serialization;

namespace Alastack.HmacAuth;

/// <summary>
/// An exception which indicates Invalid server timestamp hash.
/// </summary>
[Serializable]
public class HawkTimestampException : Exception
{
    /// <summary>
    /// Server timestamp
    /// </summary>
    public long Timestamp { get; }

    public HawkTimestampException(string message, long ts)
        : base(message)
    {
        Timestamp = ts;
    }
}