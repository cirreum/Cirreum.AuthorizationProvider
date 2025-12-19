namespace Cirreum.AuthorizationProvider;

/// <summary>
/// Manages the mapping between JWT audiences and their corresponding authentication schemes,
/// as well as header-based schemes for non-JWT authentication (e.g., API keys).
/// Provides a centralized registry for resolving which authentication scheme should be used
/// for validating tokens with specific audience claims or requests with specific headers.
/// </summary>
public sealed class AuthorizationSchemeRegistry {
	private readonly Dictionary<string, string> _audienceSchemeMap = [];
	private readonly Dictionary<string, string> _headerSchemeMap = new(StringComparer.OrdinalIgnoreCase);
	private readonly HashSet<string> _customSchemes = [];

	/// <summary>
	/// Registers an authentication scheme for a specific JWT audience claim.
	/// Used by audience-based providers (Entra, Okta, Ping, etc.).
	/// </summary>
	/// <param name="audience">The audience claim value to associate with the scheme.</param>
	/// <param name="scheme">The authentication scheme name to use for this audience.</param>
	public void RegisterAudienceScheme(string audience, string scheme) {
		_audienceSchemeMap[audience] = scheme;
	}

	/// <summary>
	/// Registers an authentication scheme for a specific HTTP header.
	/// Used by header-based providers (API keys, etc.).
	/// </summary>
	/// <param name="headerName">The HTTP header name to associate with the scheme.</param>
	/// <param name="scheme">The authentication scheme name to use when this header is present.</param>
	public void RegisterHeaderScheme(string headerName, string scheme) {
		_headerSchemeMap[headerName] = scheme;
	}

	/// <summary>
	/// Registers a custom authentication scheme that uses its own routing logic.
	/// Used by schemes like SignedRequest that check multiple headers.
	/// </summary>
	/// <param name="scheme">The authentication scheme name.</param>
	public void RegisterCustomScheme(string scheme) {
		_customSchemes.Add(scheme);
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
	/// Resolves the authentication scheme associated with a given HTTP header.
	/// </summary>
	/// <param name="headerName">The HTTP header name to look up.</param>
	/// <returns>
	/// The authentication scheme name if a mapping exists; otherwise, <see langword="null"/>.
	/// </returns>
	public string? GetSchemeForHeader(string headerName) {
		return _headerSchemeMap.TryGetValue(headerName, out var scheme) ? scheme : null;
	}

	/// <summary>
	/// Gets all registered header-based scheme mappings.
	/// </summary>
	/// <value>
	/// A read-only dictionary mapping header names to authentication scheme names.
	/// </value>
	public IReadOnlyDictionary<string, string> HeaderSchemes => _headerSchemeMap;

	/// <summary>
	/// Gets all registered custom scheme names.
	/// </summary>
	public IReadOnlySet<string> CustomSchemes => _customSchemes;

	/// <summary>
	/// Gets the collection of all registered authentication schemes.
	/// </summary>
	/// <value>
	/// A read-only set containing all unique authentication scheme names that have been registered,
	/// including audience-based, header-based, and custom schemes.
	/// </value>
	public IReadOnlySet<string> Schemes =>
		_audienceSchemeMap.Values
			.Concat(_headerSchemeMap.Values)
			.Concat(_customSchemes)
			.ToHashSet();
}
