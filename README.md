[![](https://img.shields.io/nuget/v/soenneker.hashing.sha256.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.hashing.sha256/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hashing.sha256/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.hashing.sha256/actions/workflows/publish-package.yml)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.hashing.sha256/build-and-test.yml?style=for-the-badge&label=build)](https://github.com/soenneker/soenneker.hashing.sha256/actions/workflows/build-and-test.yml)
[![](https://img.shields.io/nuget/dt/soenneker.hashing.sha256.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.hashing.sha256/)

# Soenneker.Hashing.Sha256

Fast, dependency-light SHA-256 hashing and constant-time verification for bytes, UTF-8 text, streams, and files.

Results returned as text are canonical 64-character lowercase hexadecimal strings. Hexadecimal verification accepts either casing.

> SHA-256 is designed for content integrity, fingerprints, and deterministic identifiers. It is not suitable for password storage; use a password-hashing algorithm such as Argon2id, bcrypt, or PBKDF2 instead.

## Installation

```bash
dotnet add package Soenneker.Hashing.Sha256
```

## Registration

```csharp
services.AddSha256HashingUtilAsSingleton();
```

Scoped registration is also available through `AddSha256HashingUtilAsScoped()`.

## Text and bytes

```csharp
ISha256HashingUtil sha256 = serviceProvider.GetRequiredService<ISha256HashingUtil>();

string textHash = sha256.Hash("hello world");
string bytesHash = sha256.HashToString("hello world"u8);

Span<byte> digest = stackalloc byte[32];
sha256.TryHash("hello world"u8, digest, out int bytesWritten);
```

Text is always encoded as UTF-8 without a byte-order mark.

## Verification

```csharp
string expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

bool matches = sha256.Verify("hello world", expected);
```

Digest comparison uses `CryptographicOperations.FixedTimeEquals`.

## Streams and files

```csharp
string fileHash = await sha256.HashFile("archive.zip", cancellationToken);
bool fileMatches = await sha256.VerifyFile("archive.zip", expectedHash, cancellationToken);

await using Stream stream = File.OpenRead("archive.zip");
byte[] digest = await sha256.Hash(stream, cancellationToken);
```

Stream hashing begins at the stream's current position and consumes it through the end. Streams supplied by the caller are not disposed.
