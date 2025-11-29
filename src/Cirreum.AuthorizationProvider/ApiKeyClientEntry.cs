namespace Cirreum.AuthorizationProvider;

/// <summary>
/// Represents a registered API key client with its associated configuration.
/// </summary>
/// <param name="Scheme">The authentication scheme name for this client.</param>
/// <param name="HeaderName">The HTTP header name where the API key is expected.</param>
/// <param name="Key">The expected API key value.</param>
/// <param name="ClientId">The unique identifier for this client.</param>
/// <param name="ClientName">The display name for this client.</param>
/// <param name="Roles">The roles to assign to authenticated requests from this client.</param>
public sealed record ApiKeyClientEntry(
	string Scheme,
	string HeaderName,
	string Key,
	string ClientId,
	string ClientName,
	IReadOnlyList<string> Roles);
