using Microsoft.Extensions.Options;

namespace Alastack.HmacAuth;

/// <summary>
/// Class used to validate <see cref="HmacSettings" /> instance.
/// </summary>
public class HmacSettingsValidation : IValidateOptions<HmacSettings>
{
    /// <summary>
    /// Validates a specific named options instance (or all when name is null).
    /// </summary>
    /// <param name="name">The name of the options instance being validated.</param>
    /// <param name="options">The options instance.</param>
    /// <returns>The <see cref="ValidateOptionsResult" /> result.</returns>
    public ValidateOptionsResult Validate(string? name, HmacSettings options)
    {
        string? vor = null;
        if (String.IsNullOrWhiteSpace(options.AppId))
        {
            vor = $"{nameof(options.AppId)} must not be null or whitespace.";
        }
        if (String.IsNullOrWhiteSpace(options.AppKey))
        {
            vor += $"{nameof(options.AppKey)} must not be null or whitespace.";
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
            return ValidateOptionsResult.Fail(vor);
        }

        return ValidateOptionsResult.Success;
    }
}