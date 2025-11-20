namespace Cirreum.AuthorizationProvider;

using Cirreum.AuthorizationProvider.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Abstract base class for implementing authorization provider registrars that handle
/// the registration and configuration of authorization providers within the dependency injection container.
/// </summary>
/// <typeparam name="TSettings">The type of provider settings that contains multiple instances.</typeparam>
/// <typeparam name="TInstanceSettings">The type of individual instance settings for this provider.</typeparam>
public abstract class AuthorizationProviderRegistrar<TSettings, TInstanceSettings>
	: IProviderRegistrar<TSettings, TInstanceSettings>
	where TInstanceSettings : AuthorizationProviderInstanceSettings
	where TSettings : AuthorizationProviderSettings<TInstanceSettings> {


	private static readonly Dictionary<string, string> processedInstances = [];

	/// <inheritdoc/>
	public abstract ProviderType ProviderType { get; }

	/// <inheritdoc/>
	public abstract string ProviderName { get; }

	/// <summary>
	/// Validates the provider instance settings. Override this method to implement provider-specific validation logic.
	/// </summary>
	/// <param name="settings">The instance settings to validate.</param>
	/// <remarks>
	/// This method is called during the registration process to ensure that the provider settings
	/// are valid before attempting to register the provider instance. The base implementation
	/// performs no validation and can be overridden as needed.
	/// </remarks>
	public virtual void ValidateSettings(TInstanceSettings settings) {
	}

	/// <summary>
	/// Registers all of the provider's configured services with the configuration manager.
	/// </summary>
	/// <param name="services">The DI container's service collection where other services will be registered.</param>
	/// <param name="providerSettings">An instance of the provider-specific settings populated from application settings.</param>
	/// <param name="providerSection">The root configuration object providing access to the full application configuration and where the secrets provider will be added.</param>
	/// <param name="authBuilder">The current <see cref="AuthenticationBuilder"/> instance.</param>
	/// <remarks>
	/// This method performs the complete service registration process:
	/// <list type="bullet">
	///   <item>
	///     <description>Reads provider-specific configuration settings</description>
	///   </item>
	///   <item>
	///     <description>Registers service implementations for their appropriate purpose</description>
	///   </item>
	///   <item>
	///     <description>Configures and initializes any required service dependencies</description>
	///   </item>
	/// </list>
	/// </remarks>
	public virtual void Register(
		IServiceCollection services,
		TSettings providerSettings,
		IConfigurationSection providerSection,
		AuthenticationBuilder authBuilder) {

		if (providerSettings is null || providerSettings.Instances.Count == 0) {
			return;
		}

		foreach (var (key, settings) in providerSettings.Instances) {

			var instanceSection = providerSection.GetSection($"Instances:{key}");
			if (!instanceSection.Exists()) {
				continue;
			}

			if (!settings.Enabled) {
				continue;
			}

			// Register the provider instance
			this.RegisterInstance(key, settings, services, instanceSection, authBuilder);

		}

	}

	/// <summary>
	/// Registers a single provider instance.
	/// </summary>
	/// <param name="key">The unique identifier for this provider instance, typically derived from configuration.</param>
	/// <param name="settings">The configuration settings specific to this provider instance.</param>
	/// <param name="services">The DI container's service collection where services will be registered.</param>
	/// <param name="instanceSection">The configuration section for this instance.</param>
	/// <param name="authBuilder">The current <see cref="AuthenticationBuilder"/> instance.</param>
	/// <remarks>
	/// This method handles the registration of an individual authorization provider instance:
	/// <list type="bullet">
	///   <item>
	///     <description>Validates the instance-specific settings</description>
	///   </item>
	///   <item>
	///     <description>Configures instance-specific dependencies</description>
	///   </item>
	/// </list>
	/// This method is called by <see cref="Register"/> for each configured instance, but can also be used
	/// independently to register single instances when needed.
	/// </remarks>
	public virtual void RegisterInstance(
		string key,
		TInstanceSettings settings,
		IServiceCollection services,
		IConfigurationSection instanceSection,
		AuthenticationBuilder authBuilder) {

		// Ensure no duplicate registration keys
		var providerRegistrationKey = $"Cirreum.{this.ProviderType}.{this.ProviderName}::{key}";
		if (!processedInstances.TryAdd(providerRegistrationKey, $"{settings.GetHashCode()}")) {
			throw new InvalidOperationException($"A service with the key of '{key}' has already been registered.");
		}

		// Must have settings...
		if (settings is null) {
			throw new InvalidOperationException($"Missing required settings for the service '{key}'");
		}

		// Map the key to the scheme name
		settings.Scheme = key;

		// Provider specific validation...
		this.ValidateSettings(settings);

		// Add the ServiceProvider...
		if (AuthorizationSchemeRegistry.IsApplication) {
			this.AddAuthorizationForWebApp(instanceSection, settings, authBuilder);
		} else {
			this.AddAuthorizationForWebApi(instanceSection, settings, authBuilder);
		}

		// Get the scheme registry
		var registry = services.GetAuthorizationSchemeRegistry();

		// Register the scheme for the audience
		registry.RegisterScheme(settings.Audience, settings.Scheme);

	}

	/// <summary>
	/// Base method to perform the actual registration.
	/// </summary>
	/// <param name="instanceSection">The instance configuration section that authorization setting can bind against.</param>
	/// <param name="providerSettings">The instance settings.</param>
	/// <param name="authBuilder">The current <see cref="AuthenticationBuilder"/> instance.</param>
	public abstract void AddAuthorizationForWebApi(
		IConfigurationSection instanceSection,
		TInstanceSettings providerSettings,
		AuthenticationBuilder authBuilder);

	/// <summary>
	/// Base method to perform the actual registration.
	/// </summary>
	/// <param name="instanceSection">The instance configuration section that authorization setting can bind against.</param>
	/// <param name="providerSettings">The instance settings.</param>
	/// <param name="authBuilder">The current <see cref="AuthenticationBuilder"/> instance.</param>
	public abstract void AddAuthorizationForWebApp(
		IConfigurationSection instanceSection,
		TInstanceSettings providerSettings,
		AuthenticationBuilder authBuilder);

}