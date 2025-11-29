namespace Cirreum.AuthorizationProvider.Configuration;

/// <summary>
/// Abstract base class for header-based authorization provider instance settings.
/// Used by providers that route authentication based on HTTP headers (e.g., API keys).
/// </summary>
public abstract class HeaderAuthorizationProviderInstanceSettings
	: AuthorizationProviderInstanceSettings
{
	/// <summary>
	/// Gets or sets the HTTP header name where the credential is expected.
	/// Defaults to "X-Api-Key".
	/// </summary>
	public string HeaderName { get; set; } = "X-Api-Key";

	/// <summary>
	/// Gets or sets the unique client identifier assigned to authenticated requests.
	/// This value is used as the <see cref="System.Security.Claims.ClaimTypes.NameIdentifier"/> claim.
	/// </summary>
	public string ClientId { get; set; } = "";

	/// <summary>
	/// Gets or sets the display name for the client.
	/// This value is used as the <see cref="System.Security.Claims.ClaimTypes.Name"/> claim.
	/// </summary>
	public string ClientName { get; set; } = "";

	/// <summary>
	/// Gets or sets the roles to assign to the authenticated principal.
	/// These values are used as <see cref="System.Security.Claims.ClaimTypes.Role"/> claims.
	/// </summary>
	public List<string> Roles { get; set; } = [];
}
