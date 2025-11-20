namespace Cirreum.AuthorizationProvider;

using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for <see cref="IServiceCollection"/> to support authorization provider registration.
/// </summary>
public static class ServiceCollectionExtensions {

	/// <summary>
	/// Gets the <see cref="AuthorizationSchemeRegistry"/>.
	/// </summary>
	/// <param name="services">The <see cref="IServiceCollection"/></param>
	/// <returns>The <see cref="AuthorizationSchemeRegistry"/> instance.</returns>
	public static AuthorizationSchemeRegistry GetAuthorizationSchemeRegistry(this IServiceCollection services) {

		// Look for an existing registry instance in the service collection
		var descriptor = services.FirstOrDefault(d =>
			d.ServiceType == typeof(AuthorizationSchemeRegistry));

		if (descriptor?.ImplementationInstance is AuthorizationSchemeRegistry registry) {
			return registry;
		}

		// If not found, create a new one and add it to the services
		registry = new AuthorizationSchemeRegistry();
		services.AddSingleton(registry);
		return registry;

	}

}