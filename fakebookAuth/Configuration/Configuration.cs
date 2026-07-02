using System.Text;

namespace fakebookAuth;

public sealed class JwtOptions
{
    public const string SectionName = "Jwt";

    public string Issuer { get; init; } = "fakebook-auth";
    public string Audience { get; init; } = "fakebook";
    public string SigningKey { get; init; } = string.Empty;
    public int AccessTokenMinutes { get; init; } = 15;

    public int SigningKeyBytes => Encoding.UTF8.GetByteCount(SigningKey);
}

public sealed class AuthOptions
{
    public const string SectionName = "Auth";

    public int RefreshTokenDays { get; init; } = 30;
}

public sealed class SmtpOptions
{
    public const string SectionName = "Smtp";

    public bool Enabled { get; init; }
    public string Host { get; init; } = "smtp.gmail.com";
    public int Port { get; init; } = 587;
    public bool EnableSsl { get; init; } = true;
    public string Username { get; init; } = string.Empty;
    public string Password { get; init; } = string.Empty;
    public string FromEmail { get; init; } = string.Empty;
    public string FromName { get; init; } = "Fakebook";

    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(Host) &&
        Port > 0 &&
        !string.IsNullOrWhiteSpace(Username) &&
        !string.IsNullOrWhiteSpace(Password) &&
        !string.IsNullOrWhiteSpace(FromEmail);
}

public sealed class SnowflakeOptions
{
    public const string SectionName = "Snowflake";

    public int WorkerId { get; init; }
}
