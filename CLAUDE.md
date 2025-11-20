# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is **Cirreum.AuthorizationProvider**, a .NET 10.0 class library that provides authorization provider abstractions for the Cirreum ecosystem. It's part of the larger Cirreum Core framework and handles authentication scheme registration and authorization provider configuration.

## Build Commands

```bash
# Build the solution
dotnet build Cirreum.AuthorizationProvider.slnx

# Build specific projects
dotnet build src/Cirreum.AuthorizationProvider/Cirreum.AuthorizationProvider.csproj

# Run tests (when test projects are added)
dotnet test

# Create NuGet packages (local release builds use version 1.0.100-rc)
dotnet pack --configuration Release
```

## Architecture

### Core Components

**AuthorizationProviderRegistrar<TSettings, TInstanceSettings>** (`AuthorizationProviderRegistrar.cs:8`)
- Abstract base class for implementing authorization provider registrars
- Handles provider instance registration with duplicate detection
- Supports both Web API and Web App authorization patterns
- Manages scheme-to-audience mappings via AuthorizationSchemeRegistry

**AuthorizationSchemeRegistry** (`AuthorizationSchemeRegistry.cs:8`)
- Singleton service that manages JWT audience-to-scheme mappings
- Provides centralized scheme resolution for multi-tenant scenarios
- Static `IsApplication` flag distinguishes Web App vs Web API contexts

**Configuration Classes**
- `AuthorizationProviderSettings<T>`: Base settings class with provider instances collection
- `AuthorizationProviderInstanceSettings`: Base instance settings with Scheme, Enabled, and Audience properties

### Key Patterns

1. **Provider Registration Pattern**: Each authorization provider implements `AuthorizationProviderRegistrar<TSettings, TInstanceSettings>` to handle:
   - Settings validation via `ValidateSettings()`
   - Instance registration with deduplication
   - Separate Web API vs Web App authentication configuration

2. **Scheme Registry Pattern**: Centralized mapping between JWT audiences and authentication schemes enables multi-tenant authorization where different audiences use different validation mechanisms.

3. **Instance-Based Configuration**: Providers support multiple named instances, each with their own settings and audience mappings.

## Dependencies

- **Cirreum.Providers**: Base provider abstractions and contracts
- **Microsoft.AspNetCore.App**: ASP.NET Core framework for authentication/authorization
- **Microsoft.Extensions.DependencyInjection**: Dependency injection abstractions

## Project Structure

```
src/Cirreum.AuthorizationProvider/           # Main library
├── AuthorizationProviderRegistrar.cs        # Base provider registrar
├── AuthorizationSchemeRegistry.cs           # Scheme-audience mapping
├── Configuration/                           # Configuration models
│   ├── AuthorizationProviderSettings.cs    # Base provider settings
│   └── AuthorizationProviderInstanceSettings.cs # Instance settings
└── Extensions/                              # Service collection extensions
    └── ServiceCollectionExtensions.cs      # DI container extensions
```

## Development Notes

- Uses .NET 10.0 with latest C# language version
- Nullable reference types enabled
- CI/CD aware build configuration (detects Azure DevOps, GitHub Actions)
- Currently contains only the main library project (no test projects yet)