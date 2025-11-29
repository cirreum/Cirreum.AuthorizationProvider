namespace Cirreum.AuthorizationProvider;

using Cirreum.AuthorizationProvider.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Abstract base class for audience-based authorization provider registrars.
/// Used by providers that route authentication based on JWT audience claims (e.g., Entra, Okta, Ping).
/// </summary>
/// <typeparam name="TSettings">The type of provider settings that contains multiple instances.</typeparam>
/// <typeparam name="TInstanceSettings">The type of individual instance settings for this provider.</typeparam>
public abstract class AudienceAuthorizationProviderRegistrar<TSettings, TInstanceSettings>
	: AuthorizationProviderRegistrar<TSettings, TInstanceSettings>
	where TInstanceSettings : AudienceAuthorizationProviderInstanceSettings
	where TSettings : AuthorizationProviderSettings<TInstanceSettings> {
	/// <inheritdoc/>
	protected override void RegisterScheme(
		string key,
		TInstanceSettings settings,
		IServiceCollection services,
		IConfigurationSection instanceSection,
		AuthenticationBuilder authBuilder) {
		// Add the authentication scheme via derived class
		if (ProviderContext.GetRuntimeType() == ProviderRuntimeType.WebApp) {
			this.AddAuthorizationForWebApp(instanceSection, settings, authBuilder);
		} else {
			this.AddAuthorizationForWebApi(instanceSection, settings, authBuilder);
		}

		// Register the scheme for the audience in the registry
		var registry = services.GetAuthorizationSchemeRegistry();
		registry.RegisterAudienceScheme(settings.Audience, settings.Scheme);
	}

	/// <summary>
	/// Adds the authentication scheme configuration for Web API applications.
	/// </summary>
	/// <param name="instanceSection">The instance configuration section for binding.</param>
	/// <param name="providerSettings">The instance settings.</param>
	/// <param name="authBuilder">The current <see cref="AuthenticationBuilder"/> instance.</param>
	public abstract void AddAuthorizationForWebApi(
		IConfigurationSection instanceSection,
		TInstanceSettings providerSettings,
		AuthenticationBuilder authBuilder);

	/// <summary>
	/// Adds the authentication scheme configuration for Web App (interactive) applications.
	/// </summary>
	/// <param name="instanceSection">The instance configuration section for binding.</param>
	/// <param name="providerSettings">The instance settings.</param>
	/// <param name="authBuilder">The current <see cref="AuthenticationBuilder"/> instance.</param>
	public abstract void AddAuthorizationForWebApp(
		IConfigurationSection instanceSection,
		TInstanceSettings providerSettings,
		AuthenticationBuilder authBuilder);
}
