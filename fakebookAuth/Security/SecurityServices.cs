using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

namespace fakebookAuth;

public interface IPasswordHasher
{
    string Hash(string password);
    bool Verify(string password, string passwordHash);
}

public sealed class BCryptPasswordHasher : IPasswordHasher
{
    public string Hash(string password) => BCrypt.Net.BCrypt.HashPassword(password);

    public bool Verify(string password, string passwordHash)
    {
        try
        {
            return BCrypt.Net.BCrypt.Verify(password, passwordHash);
        }
        catch (Exception)
        {
            return false;
        }
    }
}

public interface ITokenService
{
    string CreateAccessToken(IdentityUser user, long? sessionId = null);
    string CreateRefreshToken();
    bool TryValidateAccessToken(string token, out AccessTokenPrincipal? principal);
}

public sealed record AccessTokenPrincipal(long UserId, long? SessionId);

public sealed class TokenService(IOptions<JwtOptions> options) : ITokenService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly JwtOptions _options = options.Value;

    public string CreateAccessToken(IdentityUser user, long? sessionId = null)
    {
        var now = DateTimeOffset.UtcNow;
        var expiresAt = now.AddMinutes(_options.AccessTokenMinutes);

        var header = new Dictionary<string, object?>
        {
            ["alg"] = "HS256",
            ["typ"] = "JWT"
        };

        var payload = new Dictionary<string, object?>
        {
            ["iss"] = _options.Issuer,
            ["aud"] = _options.Audience,
            ["sub"] = user.UserId.ToString(CultureInfo.InvariantCulture),
            ["user_id"] = user.UserId,
            ["username"] = user.Username,
            ["name"] = user.DisplayName,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["nbf"] = now.ToUnixTimeSeconds(),
            ["exp"] = expiresAt.ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N")
        };

        if (sessionId is not null)
        {
            payload["sid"] = sessionId.Value;
        }

        var unsignedToken = $"{EncodeJson(header)}.{EncodeJson(payload)}";
        var signature = Sign(unsignedToken, _options.SigningKey);

        return $"{unsignedToken}.{signature}";
    }

    public string CreateRefreshToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(64);
        return WebEncoders.Base64UrlEncode(bytes);
    }

    public bool TryValidateAccessToken(string token, out AccessTokenPrincipal? principal)
    {
        principal = null;

        try
        {
            var parts = token.Split('.');
            if (parts.Length != 3)
            {
                return false;
            }

            var unsignedToken = $"{parts[0]}.{parts[1]}";
            var expectedSignature = Sign(unsignedToken, _options.SigningKey);
            var expectedBytes = Encoding.ASCII.GetBytes(expectedSignature);
            var actualBytes = Encoding.ASCII.GetBytes(parts[2]);

            if (expectedBytes.Length != actualBytes.Length ||
                !CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes))
            {
                return false;
            }

            using var header = JsonDocument.Parse(WebEncoders.Base64UrlDecode(parts[0]));
            if (!header.RootElement.TryGetProperty("alg", out var alg) ||
                alg.GetString() != "HS256")
            {
                return false;
            }

            using var payload = JsonDocument.Parse(WebEncoders.Base64UrlDecode(parts[1]));
            var root = payload.RootElement;

            if (!root.TryGetProperty("iss", out var issuer) ||
                issuer.GetString() != _options.Issuer ||
                !root.TryGetProperty("aud", out var audience) ||
                audience.GetString() != _options.Audience)
            {
                return false;
            }

            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (!root.TryGetProperty("exp", out var expiresAt) ||
                expiresAt.GetInt64() <= now)
            {
                return false;
            }

            if (root.TryGetProperty("nbf", out var notBefore) &&
                notBefore.GetInt64() > now)
            {
                return false;
            }

            if (!root.TryGetProperty("user_id", out var userIdElement) ||
                !userIdElement.TryGetInt64(out var userId))
            {
                return false;
            }

            long? sessionId = null;
            if (root.TryGetProperty("sid", out var sessionElement) &&
                sessionElement.TryGetInt64(out var parsedSessionId))
            {
                sessionId = parsedSessionId;
            }

            principal = new AccessTokenPrincipal(userId, sessionId);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string EncodeJson(object value)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        return WebEncoders.Base64UrlEncode(json);
    }

    private static string Sign(string token, string signingKey)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(signingKey));
        var signature = hmac.ComputeHash(Encoding.ASCII.GetBytes(token));
        return WebEncoders.Base64UrlEncode(signature);
    }
}

public interface ISnowflakeIdGenerator
{
    long NewId();
}

public sealed class SnowflakeIdGenerator(IOptions<SnowflakeOptions> options) : ISnowflakeIdGenerator
{
    private const long EpochMilliseconds = 1704067200000L;
    private const int WorkerIdShift = 12;
    private const int TimestampShift = 22;
    private const long SequenceMask = 4095L;

    private readonly object _sync = new();
    private readonly long _workerId = options.Value.WorkerId;
    private long _lastTimestamp = -1L;
    private long _sequence;

    public long NewId()
    {
        lock (_sync)
        {
            var timestamp = CurrentMilliseconds();

            if (timestamp < _lastTimestamp)
            {
                throw new InvalidOperationException("System clock moved backwards while generating a Snowflake ID.");
            }

            if (timestamp == _lastTimestamp)
            {
                _sequence = (_sequence + 1) & SequenceMask;
                if (_sequence == 0)
                {
                    timestamp = WaitForNextMillisecond(_lastTimestamp);
                }
            }
            else
            {
                _sequence = 0;
            }

            _lastTimestamp = timestamp;

            return ((timestamp - EpochMilliseconds) << TimestampShift) |
                   (_workerId << WorkerIdShift) |
                   _sequence;
        }
    }

    private static long WaitForNextMillisecond(long lastTimestamp)
    {
        var timestamp = CurrentMilliseconds();
        while (timestamp <= lastTimestamp)
        {
            Thread.SpinWait(128);
            timestamp = CurrentMilliseconds();
        }

        return timestamp;
    }

    private static long CurrentMilliseconds() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
}

public static class TokenHashing
{
    public static string Sha256Hex(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}

public static class OtpGenerator
{
    public static string SixDigitCode() =>
        RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6", CultureInfo.InvariantCulture);
}
