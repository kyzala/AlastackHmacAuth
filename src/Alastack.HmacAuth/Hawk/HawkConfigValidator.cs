namespace Alastack.HmacAuth;

/// <summary>
/// Class used to validate <see cref="HawkSettings" /> instance.
/// </summary>
public class HawkConfigValidator : IConfigValidator<HawkSettings>
{
    /// <inheritdoc />
    public ConfigValidationResult Validate(HawkSettings options)
    {
        string? validationMessage = null;
        if (String.IsNullOrWhiteSpace(options.AuthId))
        {
            validationMessage = $"{nameof(options.AuthId)} must not be null or whitespace.";
        }
        if (String.IsNullOrWhiteSpace(options.AuthKey))
        {
            validationMessage += $"{nameof(options.AuthKey)} must not be null or whitespace.";
        }
        if (String.IsNullOrWhiteSpace(options.MacAlgorithm))
        {
            validationMessage += $"{nameof(options.MacAlgorithm)} must not be null or whitespace.";
        }
        if (String.IsNullOrWhiteSpace(options.MacAlgorithm))
        {
            validationMessage += $"{nameof(options.MacAlgorithm)} must not be null or whitespace.";
        }

        if (validationMessage != null)
        {
            return ConfigValidationResult.Fail(validationMessage);
        }

        return ConfigValidationResult.Success;
    }
}