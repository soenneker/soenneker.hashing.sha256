using Soenneker.Hashing.Sha256.Abstract;
using System;
using System.Buffers;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Soenneker.Hashing.Sha256;

public sealed class Sha256HashingUtil : ISha256HashingUtil
{
    private const int _digestLength = 32;
    private const int _hexLength = _digestLength * 2;
    private const int _stackallocThreshold = 256;

    private static readonly Encoding _utf8 = Encoding.UTF8;

    public byte[] Hash(ReadOnlySpan<byte> data) => SHA256.HashData(data);

    public bool TryHash(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten) =>
        SHA256.TryHashData(data, destination, out bytesWritten);

    public string HashToString(ReadOnlySpan<byte> data)
    {
        Span<byte> hash = stackalloc byte[_digestLength];
        SHA256.HashData(data, hash);
        return ToLowerHex(hash);
    }

    public string Hash(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return Hash(value.AsSpan());
    }

    public string Hash(ReadOnlySpan<char> value)
    {
        int byteCount = _utf8.GetByteCount(value);
        byte[]? rented = null;
        Span<byte> utf8 = byteCount <= _stackallocThreshold
            ? stackalloc byte[byteCount]
            : (rented = ArrayPool<byte>.Shared.Rent(byteCount)).AsSpan(0, byteCount);

        try
        {
            _utf8.GetBytes(value, utf8);
            return HashToString(utf8);
        }
        finally
        {
            if (rented is not null)
                ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }

    public async ValueTask<byte[]> Hash(Stream stream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        return await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<string> HashToString(Stream stream, CancellationToken cancellationToken = default)
    {
        byte[] hash = await Hash(stream, cancellationToken).ConfigureAwait(false);
        return ToLowerHex(hash);
    }

    public async ValueTask<byte[]> HashFileToByteArray(string path, CancellationToken cancellationToken = default)
    {
        ValidatePath(path);

        await using FileStream stream = OpenFile(path);
        return await Hash(stream, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<string> HashFile(string path, CancellationToken cancellationToken = default)
    {
        byte[] hash = await HashFileToByteArray(path, cancellationToken).ConfigureAwait(false);
        return ToLowerHex(hash);
    }

    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> expectedHash)
    {
        if (expectedHash.Length != _digestLength)
            return false;

        Span<byte> actualHash = stackalloc byte[_digestLength];
        SHA256.HashData(data, actualHash);
        return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
    }

    public bool Verify(string value, string expectedHash)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(expectedHash);
        return Verify(value.AsSpan(), expectedHash.AsSpan());
    }

    public bool Verify(ReadOnlySpan<char> value, ReadOnlySpan<char> expectedHash)
    {
        Span<byte> decodedHash = stackalloc byte[_digestLength];

        if (!TryDecodeHash(expectedHash, decodedHash))
            return false;

        int byteCount = _utf8.GetByteCount(value);
        byte[]? rented = null;
        Span<byte> utf8 = byteCount <= _stackallocThreshold
            ? stackalloc byte[byteCount]
            : (rented = ArrayPool<byte>.Shared.Rent(byteCount)).AsSpan(0, byteCount);

        try
        {
            _utf8.GetBytes(value, utf8);
            return Verify(utf8, decodedHash);
        }
        finally
        {
            if (rented is not null)
                ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }

    public async ValueTask<bool> Verify(Stream stream, ReadOnlyMemory<byte> expectedHash, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);

        if (expectedHash.Length != _digestLength)
            return false;

        byte[] actualHash = await Hash(stream, cancellationToken).ConfigureAwait(false);
        return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash.Span);
    }

    public async ValueTask<bool> VerifyFile(string path, string expectedHash, CancellationToken cancellationToken = default)
    {
        ValidatePath(path);
        ArgumentNullException.ThrowIfNull(expectedHash);

        var decodedHash = new byte[_digestLength];

        if (!TryDecodeHash(expectedHash.AsSpan(), decodedHash))
            return false;

        await using FileStream stream = OpenFile(path);
        return await Verify(stream, decodedHash, cancellationToken).ConfigureAwait(false);
    }

    private static FileStream OpenFile(string path) => new(path, new FileStreamOptions
    {
        Mode = FileMode.Open,
        Access = FileAccess.Read,
        Share = FileShare.Read,
        Options = FileOptions.Asynchronous | FileOptions.SequentialScan
    });

    private static void ValidatePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("A file path is required.", nameof(path));
    }

    private static string ToLowerHex(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(bytes);

    private static bool TryDecodeHash(ReadOnlySpan<char> value, Span<byte> destination)
    {
        if (value.Length != _hexLength || destination.Length < _digestLength)
            return false;

        for (var i = 0; i < _digestLength; i++)
        {
            int high = FromHex(value[i * 2]);
            int low = FromHex(value[(i * 2) + 1]);

            if ((high | low) < 0)
                return false;

            destination[i] = (byte)((high << 4) | low);
        }

        return true;
    }

    private static int FromHex(char value)
    {
        if (value is >= '0' and <= '9')
            return value - '0';

        value = (char)(value | 0x20);
        return value is >= 'a' and <= 'f' ? value - 'a' + 10 : -1;
    }
}
