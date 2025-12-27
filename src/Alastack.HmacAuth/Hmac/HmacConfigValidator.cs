namespace Alastack.HmacAuth;

/// <summary>
/// Class used to validate <see cref="HmacSettings" /> instance.
/// </summary>
public class HmacConfigValidator : IConfigValidator<HmacSettings>
{
    /// <inheritdoc />
    public ValidateConfigResult Validate(HmacSettings options)
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
            return ValidateConfigResult.Fail(vor);
        }

        return ValidateConfigResult.Success;
    }
}