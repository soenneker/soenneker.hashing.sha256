using AwesomeAssertions;
using Soenneker.Hashing.Sha256.Abstract;
using Soenneker.Tests.HostedUnit;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace Soenneker.Hashing.Sha256.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public sealed class Sha256HashingUtilTests : HostedUnitTest
{
    private readonly ISha256HashingUtil _util;

    public Sha256HashingUtilTests(Host host) : base(host)
    {
        _util = Resolve<ISha256HashingUtil>(true);
    }

    [Test]
    public void Hash_matches_empty_test_vector()
    {
        _util.Hash("").Should().Be("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    [Test]
    public void Hash_matches_abc_test_vector()
    {
        _util.Hash("abc").Should().Be("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    [Test]
    public void Hash_uses_utf8_for_text()
    {
        const string value = "Hello, 世界 👋";

        _util.Hash(value).Should().Be(_util.HashToString(Encoding.UTF8.GetBytes(value)));
    }

    [Test]
    public void TryHash_writes_digest_to_destination()
    {
        Span<byte> destination = stackalloc byte[32];

        bool result = _util.TryHash("abc"u8, destination, out int bytesWritten);

        result.Should().BeTrue();
        bytesWritten.Should().Be(32);
        destination.ToArray().Should().BeEquivalentTo(Convert.FromHexString(_util.Hash("abc")));
    }

    [Test]
    public void TryHash_rejects_small_destination()
    {
        Span<byte> destination = stackalloc byte[31];

        bool result = _util.TryHash("abc"u8, destination, out int bytesWritten);

        result.Should().BeFalse();
        bytesWritten.Should().Be(0);
    }

    [Test]
    public void Verify_accepts_matching_uppercase_hex()
    {
        string expected = _util.Hash("verify me").ToUpperInvariant();

        _util.Verify("verify me", expected).Should().BeTrue();
    }

    [Test]
    public void Verify_rejects_mismatch_and_invalid_hex()
    {
        _util.Verify("verify me", _util.Hash("different")).Should().BeFalse();
        _util.Verify("verify me", "not-a-sha256-digest").Should().BeFalse();
    }

    [Test]
    public async Task Stream_hashing_starts_at_current_position()
    {
        await using var stream = new MemoryStream("skipabc"u8.ToArray());
        stream.Position = 4;

        string result = await _util.HashToString(stream);

        result.Should().Be(_util.Hash("abc"));
    }

    [Test]
    public async Task Verify_stream_compares_binary_digest()
    {
        byte[] data = "stream value"u8.ToArray();
        byte[] expected = _util.Hash(data);
        await using var stream = new MemoryStream(data);

        bool result = await _util.Verify(stream, expected);

        result.Should().BeTrue();
    }

    [Test]
    public async Task File_hashing_and_verification_match_text_hashing()
    {
        string path = Path.GetTempFileName();

        try
        {
            await File.WriteAllTextAsync(path, "file value", new UTF8Encoding(false));

            string hash = await _util.HashFile(path);

            hash.Should().Be(_util.Hash("file value"));
            (await _util.VerifyFile(path, hash)).Should().BeTrue();
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Test]
    public void Null_text_throws()
    {
        Action hash = () => _util.Hash((string)null!);
        Action verifyValue = () => _util.Verify(null!, "hash");
        Action verifyHash = () => _util.Verify("value", null!);

        hash.Should().Throw<ArgumentNullException>();
        verifyValue.Should().Throw<ArgumentNullException>();
        verifyHash.Should().Throw<ArgumentNullException>();
    }
}
