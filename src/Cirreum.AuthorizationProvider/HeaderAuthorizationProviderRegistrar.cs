namespace Cirreum.AuthorizationProvider;

using Cirreum.AuthorizationProvider.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Abstract base class for header-based authorization provider registrars.
/// Used by providers that route authentication based on HTTP headers (e.g., API keys).
/// </summary>
/// <typeparam name="TSettings">The type of provider settings that contains multiple instances.</typeparam>
/// <typeparam name="TInstanceSettings">The type of individual instance settings for this provider.</typeparam>
public abstract class HeaderAuthorizationProviderRegistrar<TSettings, TInstanceSettings>
	: AuthorizationProviderRegistrar<TSettings, TInstanceSettings>
	where TInstanceSettings : HeaderAuthorizationProviderInstanceSettings
	where TSettings : AuthorizationProviderSettings<TInstanceSettings> {
	/// <inheritdoc/>
	protected override void RegisterScheme(
		string key,
		TInstanceSettings settings,
		IServiceCollection services,
		IConfigurationSection instanceSection,
		AuthenticationBuilder authBuilder) {

		// Validate required header-based provider properties
		if (string.IsNullOrWhiteSpace(settings.HeaderName)) {
			throw new InvalidOperationException(
				$"Header-based provider instance '{key}' requires a HeaderName.");
		}

		if (string.IsNullOrWhiteSpace(settings.ClientId)) {
			throw new InvalidOperationException(
				$"Header-based provider instance '{key}' requires a ClientId.");
		}

		var clientName = string.IsNullOrWhiteSpace(settings.ClientName)
			? settings.ClientId
			: settings.ClientName;

		// Get the client registry and register this client
		var clientRegistry = services.GetApiKeyClientRegistry();

		// Get the key from configuration (should come from Key Vault in production)
		var apiKey = instanceSection.GetValue<string>("Key")
			?? throw new InvalidOperationException(
				$"Header-based provider instance '{key}' requires a Key in configuration.");

		// Register the client entry
		clientRegistry.Register(new ApiKeyClientEntry(
			settings.Scheme,
			settings.HeaderName,
			apiKey,
			settings.ClientId,
			clientName,
			settings.Roles));

		// Register the authentication scheme only once per unique header name
		var schemeRegistry = services.GetAuthorizationSchemeRegistry();
		var schemeName = $"Header:{settings.HeaderName}";

		if (schemeRegistry.GetSchemeForHeader(settings.HeaderName) is null) {
			// Add the authentication handler via derived class
			this.AddAuthenticationHandler(schemeName, settings, authBuilder);

			// Register in the scheme registry
			schemeRegistry.RegisterHeaderScheme(settings.HeaderName, schemeName);
		}
	}

	/// <summary>
	/// Adds the authentication handler for this header-based provider.
	/// </summary>
	/// <param name="schemeName">The scheme name to register.</param>
	/// <param name="settings">The instance settings.</param>
	/// <param name="authBuilder">The current <see cref="AuthenticationBuilder"/> instance.</param>
	protected abstract void AddAuthenticationHandler(
		string schemeName,
		TInstanceSettings settings,
		AuthenticationBuilder authBuilder);
}
