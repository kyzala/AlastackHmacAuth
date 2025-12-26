namespace Alastack.HmacAuth;

/// <summary>
/// A timestamp calculator abstraction.
/// </summary>
public interface ITimestampCalculator
{
    /// <summary>
    /// Calculate timestamp.
    /// </summary>
    /// <param name="timeOffset">The time offset(in seconds).</param>
    /// <returns>Timestamp(in seconds).</returns>
    long Calculate(long timeOffset);
}