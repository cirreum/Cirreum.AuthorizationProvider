namespace Cirreum.AuthorizationProvider.Configuration;

/// <summary>
/// Abstract base class for audience-based authorization provider instance settings.
/// Used by providers that route authentication based on JWT audience claims (e.g., Entra, Okta, Ping).
/// </summary>
public abstract class AudienceAuthorizationProviderInstanceSettings
	: AuthorizationProviderInstanceSettings
{
	/// <summary>
	/// Gets or sets the JWT audience claim value for this provider instance.
	/// This value is used to map incoming JWT tokens to the appropriate authentication scheme.
	/// </summary>
	public string Audience { get; set; } = "";
}
