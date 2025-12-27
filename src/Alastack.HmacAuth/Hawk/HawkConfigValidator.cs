namespace Alastack.HmacAuth;

/// <summary>
/// Class used to validate <see cref="HawkSettings" /> instance.
/// </summary>
public class HawkConfigValidator : IConfigValidator<HawkSettings>
{
    /// <inheritdoc />
    public ValidateConfigResult Validate(HawkSettings options)
    {
        string? vor = null;
        if (String.IsNullOrWhiteSpace(options.AuthId))
        {
            vor = $"{nameof(options.AuthId)} must not be null or whitespace.";
        }
        if (String.IsNullOrWhiteSpace(options.AuthKey))
        {
            vor += $"{nameof(options.AuthKey)} must not be null or whitespace.";
        }
        if (String.IsNullOrWhiteSpace(options.HmacAlgorithm))
        {
            vor += $"{nameof(options.HmacAlgorithm)} must not be null or whitespace.";
        }
        if (String.IsNullOrWhiteSpace(options.HmacAlgorithm))
        {
            vor += $"{nameof(options.HmacAlgorithm)} must not be null or whitespace.";
        }

        if (vor != null)
        {
            return ValidateConfigResult.Fail(vor);
        }

        return ValidateConfigResult.Success;
    }
}