namespace Cirreum.AuthorizationProvider;

using Cirreum.AuthorizationProvider.Configuration;
using Cirreum.Providers;
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
	private static readonly Dictionary<string, string> ProcessedInstances = [];

	/// <inheritdoc/>
	public ProviderType ProviderType => ProviderType.Authorization;

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
	/// <param name="providerSettings">An instance of the provider-specific settings populated from application settings.</param>
	/// <param name="services">The DI container's service collection where other services will be registered.</param>
	/// <param name="configuration">The root configuration object providing access to the full application configuration.</param>
	/// <param name="authBuilder">The current <see cref="AuthenticationBuilder"/> instance.</param>
	public virtual void Register(
		TSettings providerSettings,
		IServiceCollection services,
		IConfiguration configuration,
		AuthenticationBuilder authBuilder) {
		if (providerSettings is null || providerSettings.Instances.Count == 0) {
			return;
		}

		foreach (var (key, settings) in providerSettings.Instances) {
			if (!settings.Enabled) {
				continue;
			}

			this.RegisterInstance(key, settings, services, configuration, authBuilder);
		}
	}

	/// <summary>
	/// Registers a single provider instance.
	/// </summary>
	/// <param name="key">The unique identifier for this provider instance, typically derived from configuration.</param>
	/// <param name="settings">The configuration settings specific to this provider instance.</param>
	/// <param name="services">The DI container's service collection where services will be registered.</param>
	/// <param name="configuration">The root configuration object providing access to the full application configuration.</param>
	/// <param name="authBuilder">The current <see cref="AuthenticationBuilder"/> instance.</param>
	public virtual void RegisterInstance(
		string key,
		TInstanceSettings settings,
		IServiceCollection services,
		IConfiguration configuration,
		AuthenticationBuilder authBuilder) {

		// Ensure no duplicate registration keys
		var providerRegistrationKey = $"Cirreum.{this.ProviderType}.{this.ProviderName}::{key}";
		if (!ProcessedInstances.TryAdd(providerRegistrationKey, $"{settings.GetHashCode()}")) {
			throw new InvalidOperationException($"A service with the key of '{key}' has already been registered.");
		}

		// Must have settings
		if (settings is null) {
			throw new InvalidOperationException($"Missing required settings for the service '{key}'");
		}

		// Map the key to the scheme name
		settings.Scheme = key;

		// Provider specific validation
		this.ValidateSettings(settings);

		// Delegate to derived class for scheme registration
		this.RegisterScheme(key, settings, services, configuration, authBuilder);
	}

	/// <summary>
	/// Gets the configuration section path for a specific instance.
	/// </summary>
	/// <param name="instanceKey">The instance key.</param>
	/// <returns>The configuration section path.</returns>
	protected string GetInstanceSectionPath(string instanceKey) =>
		$"Cirreum:{this.ProviderType}:Providers:{this.ProviderName}:Instances:{instanceKey}";

	/// <summary>
	/// Registers the authentication scheme for this provider instance.
	/// Derived classes implement this to handle audience-based or header-based registration.
	/// </summary>
	/// <param name="key">The unique identifier for this provider instance.</param>
	/// <param name="settings">The configuration settings specific to this provider instance.</param>
	/// <param name="services">The DI container's service collection.</param>
	/// <param name="configuration">The root configuration object.</param>
	/// <param name="authBuilder">The current <see cref="AuthenticationBuilder"/> instance.</param>
	protected abstract void RegisterScheme(
		string key,
		TInstanceSettings settings,
		IServiceCollection services,
		IConfiguration configuration,
		AuthenticationBuilder authBuilder);
}
