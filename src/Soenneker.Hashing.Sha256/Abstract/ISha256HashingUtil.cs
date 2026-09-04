using System;
using System.Diagnostics.Contracts;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Soenneker.Hashing.Sha256.Abstract;

/// <summary>
/// Provides SHA-256 hashing and constant-time verification for bytes, UTF-8 text, streams, and files.
/// </summary>
/// <remarks>
/// Text is encoded as UTF-8. Hexadecimal results are always 64 lowercase characters.
/// SHA-256 is suitable for content integrity and identifiers, but not for password storage.
/// </remarks>
public interface ISha256HashingUtil
{
    /// <summary>
    /// Computes the SHA-256 digest of a byte sequence.
    /// </summary>
    /// <param name="data">The bytes to hash.</param>
    /// <returns>The 32-byte digest.</returns>
    [Pure]
    byte[] Hash(ReadOnlySpan<byte> data);

    /// <summary>
    /// Attempts to compute the SHA-256 digest into a caller-provided buffer.
    /// </summary>
    /// <param name="data">The bytes to hash.</param>
    /// <param name="destination">The destination, which must be at least 32 bytes long.</param>
    /// <param name="bytesWritten">Receives 32 on success; otherwise, zero.</param>
    /// <returns><see langword="true"/> when the destination is large enough; otherwise, <see langword="false"/>.</returns>
    [Pure]
    bool TryHash(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten);

    /// <summary>
    /// Computes the SHA-256 digest of a byte sequence as lowercase hexadecimal.
    /// </summary>
    /// <param name="data">The bytes to hash.</param>
    /// <returns>The 64-character lowercase hexadecimal digest.</returns>
    [Pure]
    string HashToString(ReadOnlySpan<byte> data);

    /// <summary>
    /// Computes the SHA-256 digest of UTF-8 text as lowercase hexadecimal.
    /// </summary>
    /// <param name="value">The text to hash.</param>
    /// <returns>The 64-character lowercase hexadecimal digest.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="value"/> is <see langword="null"/>.</exception>
    [Pure]
    string Hash(string value);

    /// <summary>
    /// Computes the SHA-256 digest of UTF-8 text as lowercase hexadecimal.
    /// </summary>
    /// <param name="value">The text to hash.</param>
    /// <returns>The 64-character lowercase hexadecimal digest.</returns>
    [Pure]
    string Hash(ReadOnlySpan<char> value);

    /// <summary>
    /// Asynchronously hashes a stream from its current position through its end.
    /// </summary>
    /// <param name="stream">The readable stream to hash.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns>The 32-byte digest.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="stream"/> is <see langword="null"/>.</exception>
    ValueTask<byte[]> Hash(Stream stream, CancellationToken cancellationToken = default);

    /// <summary>
    /// Asynchronously hashes a stream from its current position through its end.
    /// </summary>
    /// <param name="stream">The readable stream to hash.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns>The 64-character lowercase hexadecimal digest.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="stream"/> is <see langword="null"/>.</exception>
    ValueTask<string> HashToString(Stream stream, CancellationToken cancellationToken = default);

    /// <summary>
    /// Asynchronously hashes a file.
    /// </summary>
    /// <param name="path">The path of the file to hash.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns>The 32-byte digest.</returns>
    /// <exception cref="ArgumentException"><paramref name="path"/> is empty or whitespace.</exception>
    ValueTask<byte[]> HashFileToByteArray(string path, CancellationToken cancellationToken = default);

    /// <summary>
    /// Asynchronously hashes a file.
    /// </summary>
    /// <param name="path">The path of the file to hash.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns>The 64-character lowercase hexadecimal digest.</returns>
    /// <exception cref="ArgumentException"><paramref name="path"/> is empty or whitespace.</exception>
    ValueTask<string> HashFile(string path, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies a byte sequence against a 32-byte SHA-256 digest using a fixed-time comparison.
    /// </summary>
    /// <param name="data">The bytes to hash.</param>
    /// <param name="expectedHash">The expected 32-byte digest.</param>
    /// <returns><see langword="true"/> when the digest matches; otherwise, <see langword="false"/>.</returns>
    [Pure]
    bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> expectedHash);

    /// <summary>
    /// Verifies UTF-8 text against a hexadecimal SHA-256 digest using a fixed-time comparison.
    /// </summary>
    /// <param name="value">The text to hash.</param>
    /// <param name="expectedHash">The expected 64-character hexadecimal digest. Hex digits are case-insensitive.</param>
    /// <returns><see langword="true"/> when the digest matches; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="value"/> or <paramref name="expectedHash"/> is <see langword="null"/>.</exception>
    [Pure]
    bool Verify(string value, string expectedHash);

    /// <summary>
    /// Verifies UTF-8 text against a hexadecimal SHA-256 digest using a fixed-time comparison.
    /// </summary>
    /// <param name="value">The text to hash.</param>
    /// <param name="expectedHash">The expected 64-character hexadecimal digest. Hex digits are case-insensitive.</param>
    /// <returns><see langword="true"/> when the digest matches; otherwise, <see langword="false"/>.</returns>
    [Pure]
    bool Verify(ReadOnlySpan<char> value, ReadOnlySpan<char> expectedHash);

    /// <summary>
    /// Asynchronously verifies a stream from its current position against a 32-byte digest.
    /// </summary>
    /// <param name="stream">The readable stream to hash.</param>
    /// <param name="expectedHash">The expected 32-byte digest.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns><see langword="true"/> when the digest matches; otherwise, <see langword="false"/>.</returns>
    ValueTask<bool> Verify(Stream stream, ReadOnlyMemory<byte> expectedHash, CancellationToken cancellationToken = default);

    /// <summary>
    /// Asynchronously verifies a file against a hexadecimal SHA-256 digest.
    /// </summary>
    /// <param name="path">The path of the file to hash.</param>
    /// <param name="expectedHash">The expected 64-character hexadecimal digest. Hex digits are case-insensitive.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns><see langword="true"/> when the digest matches; otherwise, <see langword="false"/>.</returns>
    ValueTask<bool> VerifyFile(string path, string expectedHash, CancellationToken cancellationToken = default);
}
