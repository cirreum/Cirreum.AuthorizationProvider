# Cirreum Authorization Provider

[![NuGet Version](https://img.shields.io/nuget/v/Cirreum.AuthorizationProvider.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.AuthorizationProvider/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Cirreum.AuthorizationProvider.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.AuthorizationProvider/)
[![GitHub Release](https://img.shields.io/github/v/release/cirreum/Cirreum.AuthorizationProvider?style=flat-square&labelColor=1F1F1F&color=FF3B2E)](https://github.com/cirreum/Cirreum.AuthorizationProvider/releases)
[![License](https://img.shields.io/github/license/cirreum/Cirreum.AuthorizationProvider?style=flat-square&labelColor=1F1F1F&color=F2F2F2)](https://github.com/cirreum/Cirreum.AuthorizationProvider/blob/main/LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-003D8F?style=flat-square&labelColor=1F1F1F)](https://dotnet.microsoft.com/)

**Authorization provider abstractions and scheme management for the Cirreum Framework**

## Overview

**Cirreum.AuthorizationProvider** is the foundational library for implementing authorization providers within the Cirreum ecosystem. It provides the core abstractions, registration patterns, and scheme management infrastructure needed to build pluggable authorization solutions that integrate seamlessly with ASP.NET Core authentication.

### Key Features

#### 🔐 Provider Registration Pattern
A standardized approach to implementing authorization providers through the `AuthorizationProviderRegistrar<TSettings, TInstanceSettings>` abstract base class:

- **Multi-instance support** - Configure multiple instances of the same provider type with different settings
- **Duplicate detection** - Automatic prevention of duplicate registrations
- **Validation framework** - Provider-specific settings validation before registration
- **Web API/Web App differentiation** - Separate registration paths for different application types

#### 🎯 Scheme Registry System
Centralized management of JWT audience-to-authentication scheme mappings through `AuthorizationSchemeRegistry`:

- **Audience-based routing** - Map JWT audience claims to specific authentication schemes
- **Multi-tenant support** - Handle multiple authorization contexts within a single application
- **Dynamic scheme resolution** - Runtime lookup of appropriate schemes for incoming tokens

#### ⚙️ Configuration Abstractions
Flexible configuration models that support provider-specific settings while maintaining consistency:

- **Hierarchical settings** - Provider-level settings with instance-specific overrides
- **Enabled/disabled instances** - Granular control over which provider instances are active
- **Configuration binding** - Seamless integration with ASP.NET Core configuration system

### Usage Example

```csharp
// Implement a custom authorization provider
public class MyAuthProvider : AuthorizationProviderRegistrar<MyProviderSettings, MyInstanceSettings>
{
    public override ProviderType ProviderType => ProviderType.Authorization;
    public override string ProviderName => "MyProvider";

    public override void AddAuthorizationForWebApi(
        IConfigurationSection instanceSection,
        MyInstanceSettings settings,
        AuthenticationBuilder authBuilder)
    {
        authBuilder.AddJwtBearer(settings.Scheme, options =>
        {
            // Configure JWT validation for this scheme
            instanceSection.Bind(options);
        });
    }

    public override void AddAuthorizationForWebApp(
        IConfigurationSection instanceSection,
        MyInstanceSettings settings,
        AuthenticationBuilder authBuilder)
    {
        authBuilder.AddOpenIdConnect(settings.Scheme, options =>
        {
            // Configure OIDC for this scheme
            instanceSection.Bind(options);
        });
    }
}

// Register the provider
var providerSettings = configuration.GetSection("MyProvider").Get<MyProviderSettings>();
var myProvider = new MyAuthProvider();
myProvider.Register(services, providerSettings, configuration.GetSection("MyProvider"), authBuilder);
```

### Architecture

The library follows a layered architecture:

```text
AuthorizationProviderRegistrar (Base Class)
├── Provider Type Identification
├── Instance Management & Validation
├── Scheme Registry Integration
└── Web API/App Registration Hooks

AuthorizationSchemeRegistry (Singleton Service)
├── Audience → Scheme Mapping
├── Multi-tenant Resolution
└── Runtime Scheme Lookup

Configuration Models
├── Provider Settings (Multiple Instances)
└── Instance Settings (Individual Configuration)
```

### Installation

```bash
dotnet add package Cirreum.AuthorizationProvider
```

### Basic Setup

```csharp
// In Program.cs or Startup.cs
var authBuilder = services.AddAuthentication();

// Get the scheme registry for audience mapping
var registry = services.GetAuthorizationSchemeRegistry();

// Configure for web application context
AuthorizationSchemeRegistry.IsApplication = true; // or false for Web API

// Register your authorization providers
// (Implementation depends on specific provider)
```

## Contribution Guidelines

1. **Be conservative with new abstractions**  
   The API surface must remain stable and meaningful.

2. **Limit dependency expansion**  
   Only add foundational, version-stable dependencies.

3. **Favor additive, non-breaking changes**  
   Breaking changes ripple through the entire ecosystem.

4. **Include thorough unit tests**  
   All primitives and patterns should be independently testable.

5. **Document architectural decisions**  
   Context and reasoning should be clear for future maintainers.

6. **Follow .NET conventions**  
   Use established patterns from Microsoft.Extensions.* libraries.

## Versioning

Cirreum.AuthorizationProvider follows [Semantic Versioning](https://semver.org/):

- **Major** - Breaking API changes
- **Minor** - New features, backward compatible
- **Patch** - Bug fixes, backward compatible

Given its foundational role, major version bumps are rare and carefully considered.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Cirreum Foundation Framework**  
*Layered simplicity for modern .NET*