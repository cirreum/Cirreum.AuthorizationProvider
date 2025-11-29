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
A bifurcated approach to implementing authorization providers based on their routing mechanism:

- **Audience-based providers** - For OAuth/OIDC providers (Entra, Okta, Ping) that route by JWT audience claim, with separate Web API and Web App registration paths
- **Header-based providers** - For API key and similar providers that route by HTTP header presence
- **Multi-instance support** - Configure multiple instances of the same provider type with different settings
- **Duplicate detection** - Automatic prevention of duplicate registrations
- **Validation framework** - Provider-specific settings validation before registration

#### 🎯 Scheme Registry System
Centralized management of authentication scheme mappings through `AuthorizationSchemeRegistry`:

- **Audience-based routing** - Map JWT audience claims to specific authentication schemes for OAuth/OIDC providers
- **Header-based routing** - Map HTTP headers to authentication schemes for API key and similar providers
- **Multi-tenant support** - Handle multiple authorization contexts within a single application
- **Dynamic scheme resolution** - Runtime lookup of appropriate schemes for incoming requests

#### 🔑 API Key Client Registry
Secure management of API key clients through `ApiKeyClientRegistry`:

- **Multi-client support** - Multiple clients can share the same header with different keys
- **Secure validation** - Constant-time comparison to prevent timing attacks
- **Role assignment** - Configure roles per client for fine-grained authorization

#### ⚙️ Configuration Abstractions
Flexible configuration models that support provider-specific settings while maintaining consistency:

- **Hierarchical settings** - Provider-level settings with instance-specific overrides
- **Enabled/disabled instances** - Granular control over which provider instances are active
- **Configuration binding** - Seamless integration with ASP.NET Core configuration system

#### Secure Key Storage

API keys can be provided in three ways (checked in order):

1. **Direct value** - `Key` property in instance configuration (dev/testing only)
2. **Connection string** - `ConnectionStrings:{InstanceName}` in configuration (production)

For production environments, store API keys in Azure Key Vault using the connection string pattern:
```json
{
  "ConnectionStrings": {
    "LapCastBroker": "@Microsoft.KeyVault(SecretUri=https://your-vault.vault.azure.net/secrets/LapCastBrokerKey)"
  },
  "Cirreum": {
    "Authorization": {
      "Providers": {
        "ApiKey": {
          "Instances": {
            "LapCastBroker": {
              "Enabled": true,
              "HeaderName": "X-Api-Key",
              "ClientId": "lapcast-broker",
              "ClientName": "LapCast Broker",
              "Roles": ["App.System"]
            }
          }
        }
      }
    }
  }
}
```

The instance name (`LapCastBroker`) is used as the connection string key, allowing both the API and client applications to resolve the same secret from Key Vault using `configuration.GetConnectionString("LapCastBroker")`.

For local development, use user secrets:
```json
{
  "Cirreum": {
    "Authorization": {
      "Providers": {
        "ApiKey": {
          "Instances": {
            "LapCastBroker": {
              "Enabled": true,
              "HeaderName": "X-Api-Key",
              "ClientId": "lapcast-broker",
              "Key": "dev-only-key"
            }
          }
        }
      }
    }
  }
}
```

### Provider Types

| Provider Type | Base Class | Routing Mechanism | Use Case |
|---------------|------------|-------------------|----------|
| OAuth/OIDC | `AudienceAuthorizationProviderRegistrar` | JWT audience claim | User authentication, interactive flows |
| API Key | `HeaderAuthorizationProviderRegistrar` | HTTP header + key validation | Service-to-service, broker applications |

### Architecture

The library follows a layered architecture designed for extensibility:
```text
AuthorizationProviderRegistrar<TSettings, TInstanceSettings> (Base)
├── Provider Type Identification
├── Instance Management & Validation
└── Abstract RegisterScheme()
    │
    ├── AudienceAuthorizationProviderRegistrar<TSettings, TInstanceSettings>
    │   ├── Registers via AuthorizationSchemeRegistry.RegisterAudienceScheme()
    │   ├── Abstract AddAuthorizationForWebApi()
    │   └── Abstract AddAuthorizationForWebApp()
    │
    └── HeaderAuthorizationProviderRegistrar<TSettings, TInstanceSettings>
        ├── Registers via AuthorizationSchemeRegistry.RegisterHeaderScheme()
        ├── Registers clients via ApiKeyClientRegistry
        └── Abstract AddAuthenticationHandler()

AuthorizationProviderInstanceSettings (Base)
├── Scheme, Enabled, Section
│
├── AudienceAuthorizationProviderInstanceSettings
│   └── Audience
│
└── HeaderAuthorizationProviderInstanceSettings
    └── HeaderName, ClientId, ClientName, Roles
```

### Installation
```bash
dotnet add package Cirreum.AuthorizationProvider
```

### Usage

Provider implementations (Entra, API Key, etc.) live in separate Infrastructure packages. This package provides the abstractions they build upon.

#### Audience-Based Provider (OAuth/OIDC)

For providers that authenticate via JWT tokens with audience claims:
```csharp
public class MyOAuthInstanceSettings : AudienceAuthorizationProviderInstanceSettings
{
    public string TenantId { get; set; } = "";
    public string ClientId { get; set; } = "";
}

public class MyOAuthProvider 
    : AudienceAuthorizationProviderRegistrar<MyOAuthSettings, MyOAuthInstanceSettings>
{
    public override string ProviderName => "MyOAuth";

    public override void AddAuthorizationForWebApi(
        IConfigurationSection instanceSection,
        MyOAuthInstanceSettings settings,
        AuthenticationBuilder authBuilder)
    {
        authBuilder.AddJwtBearer(settings.Scheme, options =>
        {
            instanceSection.Bind(options);
        });
    }

    public override void AddAuthorizationForWebApp(
        IConfigurationSection instanceSection,
        MyOAuthInstanceSettings settings,
        AuthenticationBuilder authBuilder)
    {
        authBuilder.AddOpenIdConnect(settings.Scheme, options =>
        {
            instanceSection.Bind(options);
        });
    }
}
```

#### Header-Based Provider (API Key)

For providers that authenticate via HTTP headers:
```csharp
public class MyApiKeyInstanceSettings : HeaderAuthorizationProviderInstanceSettings
{
    // Inherits: HeaderName, ClientId, ClientName, Roles
    // Add any additional properties here
}

public class MyApiKeyProvider 
    : HeaderAuthorizationProviderRegistrar<MyApiKeySettings, MyApiKeyInstanceSettings>
{
    public override string ProviderName => "MyApiKey";

    protected override void AddAuthenticationHandler(
        string schemeName,
        MyApiKeyInstanceSettings settings,
        AuthenticationBuilder authBuilder)
    {
        authBuilder.AddScheme<MyApiKeyOptions, MyApiKeyHandler>(
            schemeName,
            options => options.HeaderName = settings.HeaderName);
    }
}
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