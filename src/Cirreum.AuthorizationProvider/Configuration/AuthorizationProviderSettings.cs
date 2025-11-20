namespace Cirreum.AuthorizationProvider.Configuration;

using Cirreum.Providers.Configuration;

/// <summary>
/// Abstract base class for authorization provider settings that contains a collection
/// of provider instances with their individual configurations.
/// </summary>
/// <typeparam name="TInstanceSettings">The type of individual instance settings for this provider.</typeparam>
public abstract class AuthorizationProviderSettings<TInstanceSettings>
	: IProviderSettings<TInstanceSettings>
	where TInstanceSettings : AuthorizationProviderInstanceSettings {

	/// <summary>
	/// Gets or sets the collection of provider instance settings keyed by instance name.
	/// Each instance represents a separate configuration of the same provider type,
	/// allowing for multiple audiences or different settings within the same application.
	/// </summary>
	public Dictionary<string, TInstanceSettings> Instances { get; set; } = [];
}