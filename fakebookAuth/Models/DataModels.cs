using System.Net;

namespace fakebookAuth;

public static class AuthConstants
{
    public const short PasswordProvider = 1;
    public const short EmailVerificationType = 1;
    public const short PasswordResetVerificationType = 3;

    public const short StatusActive = 1;
    public const short StatusDisabled = 2;
    public const short StatusDeleted = 3;
    public const short StatusUnverified = 4;
}

public sealed class IdentityUser
{
    public long UserId { get; set; }
    public string Email { get; set; } = string.Empty;
    public string? Phone { get; set; }
    public string Username { get; set; } = string.Empty;
    public DateOnly? Dob { get; set; }
    public string DisplayName { get; set; } = string.Empty;
    public short Status { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public UserType ToGraphQl() => new(UserId, Email, Username, Dob, DisplayName, Status);
}

public sealed class UserSession
{
    public long SessionId { get; set; }
    public long UserId { get; set; }
    public string RefreshTokenHash { get; set; } = string.Empty;
    public string? DeviceName { get; set; }
    public string? Os { get; set; }
    public string? Browser { get; set; }
    public IPAddress? IpAddress { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }

    public SessionType ToGraphQl(long? currentSessionId) =>
        new(
            SessionId,
            DeviceName,
            Os,
            Browser,
            IpAddress?.ToString(),
            ExpiresAt,
            CreatedAt,
            RevokedAt,
            currentSessionId == SessionId);
}

public sealed class UserCredential
{
    public long CredentialId { get; set; }
    public long UserId { get; set; }
    public short Provider { get; set; }
    public string? SecretHash { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? LastUsedAt { get; set; }
}

public sealed record ClientMetadata(
    string? DeviceName,
    string? Os,
    string? Browser,
    IPAddress? IpAddress,
    string? UserAgent)
{
    public static ClientMetadata From(HttpContext? httpContext)
    {
        var userAgent = httpContext?.Request.Headers.UserAgent.ToString();
        var ipAddress = httpContext?.Connection.RemoteIpAddress;

        return new ClientMetadata(
            UserAgentClassifier.Device(userAgent),
            UserAgentClassifier.OperatingSystem(userAgent),
            UserAgentClassifier.Browser(userAgent),
            ipAddress,
            string.IsNullOrWhiteSpace(userAgent) ? null : userAgent);
    }
}

internal static class UserAgentClassifier
{
    public static string? Browser(string? userAgent)
    {
        if (string.IsNullOrWhiteSpace(userAgent))
        {
            return null;
        }

        if (userAgent.Contains("Edg/", StringComparison.OrdinalIgnoreCase))
        {
            return "Edge";
        }

        if (userAgent.Contains("Chrome/", StringComparison.OrdinalIgnoreCase) ||
            userAgent.Contains("CriOS/", StringComparison.OrdinalIgnoreCase))
        {
            return "Chrome";
        }

        if (userAgent.Contains("Firefox/", StringComparison.OrdinalIgnoreCase) ||
            userAgent.Contains("FxiOS/", StringComparison.OrdinalIgnoreCase))
        {
            return "Firefox";
        }

        if (userAgent.Contains("Safari/", StringComparison.OrdinalIgnoreCase))
        {
            return "Safari";
        }

        return "Unknown";
    }

    public static string? OperatingSystem(string? userAgent)
    {
        if (string.IsNullOrWhiteSpace(userAgent))
        {
            return null;
        }

        if (userAgent.Contains("Windows", StringComparison.OrdinalIgnoreCase))
        {
            return "Windows";
        }

        if (userAgent.Contains("Android", StringComparison.OrdinalIgnoreCase))
        {
            return "Android";
        }

        if (userAgent.Contains("iPhone", StringComparison.OrdinalIgnoreCase) ||
            userAgent.Contains("iPad", StringComparison.OrdinalIgnoreCase))
        {
            return "iOS";
        }

        if (userAgent.Contains("Mac OS X", StringComparison.OrdinalIgnoreCase))
        {
            return "macOS";
        }

        if (userAgent.Contains("Linux", StringComparison.OrdinalIgnoreCase))
        {
            return "Linux";
        }

        return "Unknown";
    }

    public static string? Device(string? userAgent)
    {
        if (string.IsNullOrWhiteSpace(userAgent))
        {
            return null;
        }

        if (userAgent.Contains("iPad", StringComparison.OrdinalIgnoreCase) ||
            userAgent.Contains("Tablet", StringComparison.OrdinalIgnoreCase))
        {
            return "Tablet";
        }

        if (userAgent.Contains("Mobile", StringComparison.OrdinalIgnoreCase) ||
            userAgent.Contains("iPhone", StringComparison.OrdinalIgnoreCase) ||
            userAgent.Contains("Android", StringComparison.OrdinalIgnoreCase))
        {
            return "Mobile";
        }

        return "Desktop";
    }
}
