namespace Cirreum.AuthorizationProvider;

/// <summary>
/// Manages the mapping between JWT audiences and their corresponding authentication schemes.
/// Provides a centralized registry for resolving which authentication scheme should be used
/// for validating tokens with specific audience claims.
/// </summary>
public sealed class AuthorizationSchemeRegistry {
	private readonly Dictionary<string, string> _audienceSchemeMap = [];

	/// <summary>
	/// Gets or sets a value indicating whether this registry is configured for an application context.
	/// <see langword="true"/> if this is for an Application. Otherwise
	/// defaults to <see langword="false"/> for API only.
	/// </summary>
	public static bool IsApplication { get; set; }

	/// <summary>
	/// Registers an authentication scheme for a specific JWT audience claim.
	/// </summary>
	/// <param name="audience">The audience claim value to associate with the scheme.</param>
	/// <param name="scheme">The authentication scheme name to use for this audience.</param>
	public void RegisterScheme(string audience, string scheme) {
		_audienceSchemeMap[audience] = scheme;
	}

	/// <summary>
	/// Resolves the authentication scheme associated with a given JWT audience claim.
	/// </summary>
	/// <param name="audience">The audience claim value to look up.</param>
	/// <returns>
	/// The authentication scheme name if a mapping exists; otherwise, <see langword="null"/>.
	/// </returns>
	public string? GetSchemeForAudience(string audience) {
		return _audienceSchemeMap.TryGetValue(audience, out var scheme) ? scheme : null;
	}

	/// <summary>
	/// Gets the collection of all registered authentication schemes.
	/// </summary>
	/// <value>
	/// A read-only set containing all unique authentication scheme names that have been registered.
	/// </value>
	public IReadOnlySet<string> Schemes => _audienceSchemeMap.Values.ToHashSet();
}