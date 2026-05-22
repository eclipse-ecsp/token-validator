<div align="center">
  <img src="./images/logo.png" width="300" height="150"/>
</div>

# Token Validator
[![Maven Build & Sonar Analysis](https://github.com/eclipse-ecsp/token-validator/actions/workflows/maven-build.yml/badge.svg)](https://github.com/eclipse-ecsp/token-validator/actions/workflows/maven-build.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=eclipse-ecsp_token-validator&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=eclipse-ecsp_token-validator)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=eclipse-ecsp_token-validator&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=eclipse-ecsp_token-validator)
[![License Compliance](https://github.com/eclipse-ecsp/token-validator/actions/workflows/licence-compliance.yaml/badge.svg)](https://github.com/eclipse-ecsp/token-validator/actions/workflows/licence-compliance.yaml)
[![Latest Release](https://img.shields.io/github/v/release/eclipse-ecsp/token-validator?sort=semver)](https://github.com/eclipse-ecsp/token-validator/releases)


A reusable Java library for validating JWT tokens, managing public keys, and handling validation scenarios in microservices architectures.

## Overview

Token Validator provides secure, flexible, and easily integrable JWT validation for services built on Spring Boot. The validation pipeline is fully decomposed into individually replaceable steps — any stage (parsing, signature verification, claims validation, scope checking) can be overridden by implementing the corresponding interface.

## Features

- JWT signature verification using RSA and EC public keys (powered by `nimbus-jose-jwt`)
- Public key loading from JWKS endpoints and PEM files
- In-memory key cache with per-issuer refresh, LRU eviction, and no TTL-based expiry
- Exponential-backoff retry for JWKS endpoint failures via `JwksRetryStrategy`
- Configurable fallback key strategy: `DefaultFallbackKeyStrategy` resolves a default key from cache or from the file system via an optional `PemPublicKeyLoader`; `NoFallbackStrategy` fails fast
- Scheduled key refresh with configurable interval; `PublicKeyRotationEvent` triggers async per-issuer refresh on demand
- Algorithm whitelist enforcement; `alg=none` unconditionally denied
- Standard claims validation (`exp`, `nbf`, `iss`)
- Optional per-issuer audience (`aud`) validation via `AudienceValidator`
- Configurable clock-skew tolerance for `exp` and `nbf` (default zero)
- Opt-in scope validation with configurable prefix stripping
- Composable post-validation hooks (`ValidationHook`) executed in `getOrder()` precedence — no Spring Framework compile dependency required
- Spring Boot auto-configuration with `@ConditionalOnMissingBean` overrides at every step

## Prerequisites

| Requirement | Version |
|---|---|
| Java | 25 |
| Spring Boot | 4.x |
| Spring Framework | 7.x |

## Installation

[How to set up Maven](https://maven.apache.org/install.html)

[Install Java](https://www.tutorials24x7.com/java/how-to-install-openjdk-17-on-windows)
### Coding style check configuration

[checkstyle.xml](./checkstyle.xml) is the coding standard to follow while writing new/updating existing code.

Checkstyle plugin [maven-checkstyle-plugin:3.2.1](https://maven.apache.org/plugins/maven-checkstyle-plugin/) is
integrated in [pom.xml](./pom.xml) which runs in the `validate` phase and `check` goal of the maven lifecycle and fails
the build if there are any checkstyle errors in the project.

To run the checkstyle plugin, run the below maven command.

```mvn checkstyle:check```

### Running the tests

To run the tests for this system run the below maven command.

```mvn test```

Or run a specific test

```mvn test -Dtest="TheFirstUnitTest"```

To run a method from within a test

```mvn test -Dtest="TheSecondUnitTest#whenTestCase2_thenPrintTest2_1"```

## Usage
Add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>org.eclipse.ecsp</groupId>
    <artifactId>token-validator</artifactId>
    <version>0.0.1</version> // update to latest version
</dependency>
```

## Quick Start

### Spring Boot (auto-configuration)

Configure key sources in `application.yml`:

```yaml
token:
  validator:
    whitelisted-algorithms:
      - RS256
      - ES256
    clock-skew: PT30S          # optional; default PT0S (no tolerance)
    sources:
      - id: primary-idp
        issuer: https://auth.example.com
        url: https://auth.example.com/.well-known/jwks.json
        refresh-interval: PT12H
        audience: https://api.example.com   # optional; omit to skip aud validation for this issuer
      - id: default-pem
        issuer: https://auth.example.com
        location: /keys/public-key.pem
        default: true                        # used as fallback key when kid is absent
    fail-on-startup-error: true              # default true; false = log and continue with empty cache
```

Inject and use `TokenValidator`:

```java
@Autowired
TokenValidator tokenValidator;

List<TokenClaim> claims = tokenValidator.validate(jwtToken);
```

### Programmatic — simplified (no Spring)

Point the library at your JWKS endpoint. The full key-management stack (loaders, cache, fallback strategy) is auto-wired by the builder:

```java
PublicKeySource source = new PublicKeySource();
source.setId("primary-idp");
source.setIssuer("https://auth.example.com");
source.setUrl("https://auth.example.com/.well-known/jwks.json");
source.setRefreshInterval(Duration.ofHours(12));

TokenValidator tokenValidator = TokenValidatorBuilder.builder()
    .keySources(List.of(source))          // auto-wires DefaultPublicKeyManager, loaders, cache
    .build();                             // trustedIssuers derived from source.getIssuer()

List<TokenClaim> claims = tokenValidator.validate(jwtToken);
```

### Programmatic — advanced (no Spring)

Full manual wiring when you need precise control over loaders, cache, and fallback strategy:

```java
PemPublicKeyLoader pemLoader = new PemPublicKeyLoader();

PublicKeyManager publicKeyManager = new DefaultPublicKeyManager(
    List.of(new JwksPublicKeyLoader(), pemLoader),
    List.of(() -> List.of(source1, source2)),
    new InMemoryPublicKeyCache(),
    new DefaultFallbackKeyStrategy(pemLoader),  // use new NoFallbackStrategy() to fail fast
    true  // failOnStartupError — true = fail fast; false = log and continue with empty cache
);
publicKeyManager.refreshPublicKeys();  // trigger initial key load

TokenValidator tokenValidator = TokenValidatorBuilder.builder()
    .publicKeyManager(publicKeyManager)
    .whitelistedAlgorithms(List.of("RS256", "ES256"))
    .clockSkew(Duration.ofSeconds(30))   // optional; default is zero
    .build();

try {
    List<TokenClaim> claims = tokenValidator.validate(jwtToken);
} catch (InvalidTokenException | TokenExpiredException |
         InvalidSignatureException | KeyNotFoundException |
         InvalidClaimException e) {
    // handle error
}
```

## Usage Examples

### Multiple issuers

Wire multiple identity providers — each source maps to one issuer:

```java
PublicKeySource idp1 = new PublicKeySource();
idp1.setId("corporate-idp");
idp1.setIssuer("https://corp.example.com");
idp1.setUrl("https://corp.example.com/.well-known/jwks.json");
idp1.setRefreshInterval(Duration.ofHours(12));
idp1.setAudience("https://api.example.com");   // enforce aud for this issuer

PublicKeySource idp2 = new PublicKeySource();
idp2.setId("partner-idp");
idp2.setIssuer("https://partner.example.com");
idp2.setUrl("https://partner.example.com/.well-known/jwks.json");
idp2.setRefreshInterval(Duration.ofHours(6));

TokenValidator tokenValidator = TokenValidatorBuilder.builder()
    .keySources(List.of(idp1, idp2))
    .clockSkew(Duration.ofSeconds(30))
    .build();
```

### Explicit trusted issuers

Override the automatically derived issuer set:

```java
TokenValidator tokenValidator = TokenValidatorBuilder.builder()
    .keySources(List.of(source))
    .trustedIssuers(Set.of("https://auth.example.com", "https://legacy.example.com"))
    .build();
```

### Opt-in scope validation

Scope checking runs after `TokenValidator.validate()` and is invoked by the caller:

```java
List<TokenClaim> claims = tokenValidator.validate(jwtToken);

// DefaultScopeValidator(scopePrefixes) filters token scopes by prefix.
// Pass Set.of() to accept all scope values without prefix filtering.
ScopeValidator scopeValidator = new DefaultScopeValidator(Set.of("api://"));
scopeValidator.validate(claims, List.of("read:resource", "write:resource"));
// convenience overload — extracts "scope"/"scp" claims and splits space-delimited values
```

### Custom ValidationHook

Run additional checks after the standard pipeline without modifying `TokenValidator`:

```java
public class RequireSubjectHook implements ValidationHook {

    @Override
    public void validate(List<TokenClaim> claims) throws InvalidClaimException {
        boolean hasSub = claims.stream()
            .anyMatch(c -> "sub".equals(c.getName()) && c.getValue() != null);
        if (!hasSub) {
            throw new InvalidClaimException("sub claim is required");
        }
    }

    @Override
    public int getOrder() {
        return 10;   // lower values execute first
    }
}

TokenValidator tokenValidator = TokenValidatorBuilder.builder()
    .keySources(List.of(source))
    .customValidators(List.of(new RequireSubjectHook()))
    .build();
```

### Custom algorithm validator

Replace the built-in whitelist with per-issuer logic:

```java
public class PerIssuerAlgorithmValidator implements AlgorithmValidator {
    @Override
    public void validate(ParsedToken token) throws UnsupportedAlgorithmException {
        String alg = token.getAlg();
        if ("none".equalsIgnoreCase(alg)) {
            throw new UnsupportedAlgorithmException("alg=none is not permitted");
        }
        if ("ES256".equals(alg) && !"https://trusted-ec-idp.example.com".equals(token.getIss())) {
            throw new UnsupportedAlgorithmException("ES256 is only accepted from the trusted EC IDP");
        }
    }
}

TokenValidator tokenValidator = TokenValidatorBuilder.builder()
    .keySources(List.of(source))
    .algorithmValidator(new PerIssuerAlgorithmValidator())
    .build();
```

### Custom fallback key strategy

Override the fallback behaviour when a `kid` is not found in the cache:

```java
TokenValidator tokenValidator = TokenValidatorBuilder.builder()
    .publicKeyManager(new DefaultPublicKeyManager(
        List.of(new JwksPublicKeyLoader(), new PemPublicKeyLoader()),
        List.of(() -> List.of(source)),
        new InMemoryPublicKeyCache(),
        new NoFallbackStrategy(),   // fail fast — no fallback key lookup
        true
    ))
    .build();
```

### Replace individual pipeline steps

Any step can be swapped without subclassing `DefaultTokenValidator`:

```java
TokenValidator tokenValidator = TokenValidatorBuilder.builder()
    .keySources(List.of(source))
    .preprocessor(new MyTokenPreprocessor())           // step 0: input normalisation
    .algorithmValidator(new MyAlgorithmValidator())    // step 2: algorithm check
    .tokenParser(new MyCustomTokenParser())            // step 1: JWT parsing
    .signatureValidator(new MySignatureValidator())    // step 4: signature verification
    .claimsValidator(new MyClaimsValidator())          // step 5: standard claims
    .issuerValidator(new MyIssuerValidator())          // issuer check inside claims validator
    .audienceValidator(new MyAudienceValidator())      // audience check; omit to skip aud validation
    .build();
```

### Micrometer metrics

Opt in to structured observability. All meters are prefixed `token.validator` by default:

```java
TokenValidatorMetricsConfig metricsConfig = TokenValidatorMetricsConfig.builder()
    .prefix("my.service")                              // replaces global prefix
    .metricName("validations", "jwt.validations")      // rename one metric
    .disableMetric("key.cache.size")                   // suppress one meter
    .build();

TokenValidator tokenValidator = TokenValidatorBuilder.builder()
    .keySources(List.of(source))
    .metricsConfig(metricsConfig)
    .meterRegistry(meterRegistry)                      // any io.micrometer.core.instrument.MeterRegistry
    .build();
```

### Spring Boot — override one bean

All auto-configured beans respect `@ConditionalOnMissingBean`. Declare any `@Bean` to replace the default:

```java
@Configuration
public class TokenValidatorCustomization {

    // Replace the fallback strategy — everything else remains auto-configured
    @Bean
    public FallbackKeyStrategy customFallbackKeyStrategy() {
        return new NoFallbackStrategy();   // fail fast on cache miss
    }

    // Or replace the issuer validator
    @Bean
    public IssuerValidator strictIssuerValidator() {
        return new StandardIssuerValidator(
            Set.of("https://primary.example.com", "https://secondary.example.com"));
    }
}
```

## Extension Points

| Interface | Purpose | Default Implementation |
|---|---|---|
| `TokenPreprocessor` | Normalise raw input (e.g. strip `Bearer ` prefix) | `StandardTokenPreprocessor` |
| `TokenParser` | Parse JWT header/payload without verifying | `StandardTokenParser` |
| `AlgorithmValidator` | Validate JWT algorithm against whitelist | `WhitelistAlgorithmValidator` |
| `TokenSignatureValidator` | Verify JWT signature | `DefaultTokenSignatureValidator` |
| `TokenClaimsValidator` | Validate `exp`, `nbf`, `iss` (with configurable `clockSkew`) | `StandardTokenClaimsValidator` |
| `IssuerValidator` | Validate `iss` claim independently | `StandardIssuerValidator` |
| `AudienceValidator` | Validate `aud` claim per-issuer (optional) | `StandardAudienceValidator` |
| `ScopeValidator` | Validate token scopes vs required scopes | `DefaultScopeValidator` |
| `ApiScopeExtractor<C>` | Resolve required scopes from route config | Integration-provided |
| `ValidationHook` | Composable post-validation extension; ordered by `getOrder()` | Custom — registered via `TokenValidatorBuilder.customValidators()` |
| `FallbackKeyStrategy` | Resolve a key when primary `kid` lookup fails | `DefaultFallbackKeyStrategy` (cache + optional file-system) |
| `JwksRetryStrategy` | Control retry timing and limits for JWKS fetches | `ExponentialBackoffJwksRetryStrategy` |
| `PublicKeyLoader` | Load keys from a source type | `JwksPublicKeyLoader`, `PemPublicKeyLoader` |
| `PublicKeySourceProvider` | Supply key source configurations | `PropertiesPublicKeySourceProvider` |
| `PublicKeyCache` | Cache public keys | `InMemoryPublicKeyCache` |
| `PublicKeyManager` | Orchestrate key lookup and refresh | `DefaultPublicKeyManager` |

All beans are registered with `@ConditionalOnMissingBean` — declare your own `@Bean` of any interface type to override the default.

## How to contribute

Please read [CONTRIBUTING.md](./CONTRIBUTING.md) for details on our contribution guidelines, and the process for
submitting pull requests to us.

## Code of Conduct

Please read [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) for details on our code of conduct, and the process for
submitting pull requests to us.

## Contributors

<table>
  <tbody>
    <tr>
	  <td align="left" valign="top" width="14.28%"><a href="https://github.com/abhishekkumar-harman"><img src="https://github.com/abhishekkumar-harman.png" width="100px;" alt="Abhishek Kumar"/><br /><sub><b>Abhishek Kumar</b></sub></a><br /><a href="https://github.com/eclipse-ecsp/token-validator/commits?author=abhishekkumar-harman" title="Code and Documentation">📖</a> <a href="https://github.com/eclipse-ecsp/token-validator/pulls?q=is%3Apr+reviewed-by%3Aabhishekkumar-harman" title="Reviewed Pull Requests">👀</a></td>
    </tr>
  </tbody>
</table>

The list of [contributors](../../graphs/contributors) who participated in this project.

## Security Contact Information

Please read [SECURITY.md](./SECURITY.md) to raise any security related issues.

## Support

Contact the project developers via the project's "dev" list - https://accounts.eclipse.org/mailing-list/ecsp-dev

## Troubleshooting

Please read [CONTRIBUTING.md](./CONTRIBUTING.md) for details on how to raise an issue and submit a pull request to us.

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](./LICENSE) file for details

## Announcements

All updates to this component are present in our [releases page](../../releases).
For the versions available, see the [tags on this repository](../../tags).