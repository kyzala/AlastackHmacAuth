namespace Alastack.HmacAuth;

/// <summary>
/// Class used to validate <see cref="HmacSettings" /> instance.
/// </summary>
public class HmacConfigValidator : IConfigValidator<HmacSettings>
{
    /// <inheritdoc />
    public ConfigValidationResult Validate(HmacSettings options)
    {
        string? validationMessage = null;
        if (String.IsNullOrWhiteSpace(options.AppId))
        {
            validationMessage = $"{nameof(options.AppId)} must not be null or whitespace.";
        }
        if (String.IsNullOrWhiteSpace(options.AppKey))
        {
            validationMessage += $"{nameof(options.AppKey)} must not be null or whitespace.";
        }
        if (String.IsNullOrWhiteSpace(options.HmacAlgorithm))
        {
            validationMessage += $"{nameof(options.HmacAlgorithm)} must not be null or whitespace.";
        }
        if (String.IsNullOrWhiteSpace(options.HmacAlgorithm))
        {
            validationMessage += $"{nameof(options.HmacAlgorithm)} must not be null or whitespace.";
        }

        if (validationMessage != null)
        {
            return ConfigValidationResult.Fail(validationMessage);
        }

        return ConfigValidationResult.Success;
    }
}