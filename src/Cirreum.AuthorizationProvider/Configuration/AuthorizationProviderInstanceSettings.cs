namespace Cirreum.AuthorizationProvider.Configuration;

using Cirreum.Providers.Configuration;
using Microsoft.Extensions.Configuration;

/// <summary>
/// Abstract base class for authorization provider instance settings that defines
/// common configuration properties for all authorization provider instances.
/// </summary>
public abstract class AuthorizationProviderInstanceSettings
	: IProviderInstanceSettings
{
	/// <summary>
	/// Gets or sets the authentication scheme name for this provider instance.
	/// This value is typically set during registration and maps to an ASP.NET Core authentication scheme.
	/// </summary>
	public string Scheme { get; set; } = "";

	/// <summary>
	/// Gets or sets a value indicating whether this provider instance is enabled.
	/// When <see langword="false"/>, the instance will be skipped during registration.
	/// </summary>
	public bool Enabled { get; set; }

	/// <summary>
	/// Gets or sets the raw <see cref="IConfigurationSection"/> used to
	/// pass provider-specific configuration to the authorization builder.
	/// This section contains the detailed configuration for this instance.
	/// </summary>
	public IConfigurationSection? Section { get; set; }
}
