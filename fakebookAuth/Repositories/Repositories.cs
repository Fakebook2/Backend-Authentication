using System.Data.Common;
using System.Text.Json;
using Dapper;
using Npgsql;

namespace fakebookAuth;

public interface IUserRepository
{
    Task<bool> IdentifierExistsAsync(
        DbConnection connection,
        DbTransaction transaction,
        string email,
        string username,
        CancellationToken cancellationToken);

    Task InsertAsync(
        DbConnection connection,
        DbTransaction transaction,
        IdentityUser user,
        CancellationToken cancellationToken);

    Task<IdentityUser?> FindByIdentifierAsync(string identifier, CancellationToken cancellationToken);

    Task<IdentityUser?> FindByIdentifierAsync(
        DbConnection connection,
        DbTransaction transaction,
        string identifier,
        CancellationToken cancellationToken);

    Task ActivateAsync(
        DbConnection connection,
        DbTransaction transaction,
        long userId,
        CancellationToken cancellationToken);
}

public sealed class UserRepository(NpgsqlDataSource dataSource) : IUserRepository
{
    public async Task<bool> IdentifierExistsAsync(
        DbConnection connection,
        DbTransaction transaction,
        string email,
        string username,
        CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT EXISTS (
                SELECT 1
                FROM fb.id_user
                WHERE lower(email) = lower(@Email)
                   OR lower(username) = lower(@Username)
            );
            """;

        var command = new CommandDefinition(
            sql,
            new { Email = email, Username = username },
            transaction,
            cancellationToken: cancellationToken);

        return await connection.ExecuteScalarAsync<bool>(command);
    }

    public async Task InsertAsync(
        DbConnection connection,
        DbTransaction transaction,
        IdentityUser user,
        CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO fb.id_user (user_id, email, username, dob, display_name, status)
            VALUES (@UserId, @Email, @Username, @Dob, @DisplayName, @Status);
            """;

        var parameters = new
        {
            user.UserId,
            user.Email,
            user.Username,
            Dob = user.Dob?.ToDateTime(TimeOnly.MinValue),
            user.DisplayName,
            user.Status
        };

        var command = new CommandDefinition(sql, parameters, transaction, cancellationToken: cancellationToken);
        await connection.ExecuteAsync(command);
    }

    public async Task<IdentityUser?> FindByIdentifierAsync(string identifier, CancellationToken cancellationToken)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        return await FindByIdentifierAsync(connection, transaction: null!, identifier, cancellationToken);
    }

    public async Task<IdentityUser?> FindByIdentifierAsync(
        DbConnection connection,
        DbTransaction transaction,
        string identifier,
        CancellationToken cancellationToken)
    {
        var command = new CommandDefinition(
            SelectByIdentifierSql,
            new { Identifier = identifier },
            transaction,
            cancellationToken: cancellationToken);

        var user = await connection.QuerySingleOrDefaultAsync<IdentityUserRow>(command);

        return user is null
            ? null
            : new IdentityUser
            {
                UserId = user.UserId,
                Email = user.Email,
                Phone = user.Phone,
                Username = user.Username,
                Dob = user.Dob,
                DisplayName = user.DisplayName,
                Status = user.Status,
                CreatedAt = user.CreatedAt,
                UpdatedAt = user.UpdatedAt
            };
    }

    public async Task ActivateAsync(
        DbConnection connection,
        DbTransaction transaction,
        long userId,
        CancellationToken cancellationToken)
    {
        const string sql = """
            UPDATE fb.id_user
            SET status = @Status,
                updated_at = now()
            WHERE user_id = @UserId;
            """;

        var command = new CommandDefinition(
            sql,
            new { UserId = userId, Status = AuthConstants.StatusActive },
            transaction,
            cancellationToken: cancellationToken);

        await connection.ExecuteAsync(command);
    }

    private const string SelectByIdentifierSql = """
        SELECT
            user_id AS UserId,
            email AS Email,
            phone AS Phone,
            username AS Username,
            dob AS Dob,
            display_name AS DisplayName,
            status AS Status,
            created_at AS CreatedAt,
            updated_at AS UpdatedAt
        FROM fb.id_user
        WHERE lower(email) = lower(@Identifier)
           OR lower(username) = lower(@Identifier)
        LIMIT 1;
        """;

    private sealed class IdentityUserRow
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
    }
}

public interface ICredentialRepository
{
    Task InsertPasswordCredentialAsync(
        DbConnection connection,
        DbTransaction transaction,
        long credentialId,
        long userId,
        string secretHash,
        CancellationToken cancellationToken);

    Task<UserCredential?> FindPasswordCredentialAsync(long userId, CancellationToken cancellationToken);

    Task MarkUsedAsync(
        DbConnection connection,
        DbTransaction transaction,
        long credentialId,
        CancellationToken cancellationToken);
}

public sealed class CredentialRepository(NpgsqlDataSource dataSource) : ICredentialRepository
{
    public async Task InsertPasswordCredentialAsync(
        DbConnection connection,
        DbTransaction transaction,
        long credentialId,
        long userId,
        string secretHash,
        CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO fb.id_credential (credential_id, user_id, provider, secret_hash)
            VALUES (@CredentialId, @UserId, @Provider, @SecretHash);
            """;

        var parameters = new
        {
            CredentialId = credentialId,
            UserId = userId,
            Provider = AuthConstants.PasswordProvider,
            SecretHash = secretHash
        };

        var command = new CommandDefinition(sql, parameters, transaction, cancellationToken: cancellationToken);
        await connection.ExecuteAsync(command);
    }

    public async Task<UserCredential?> FindPasswordCredentialAsync(long userId, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT
                credential_id AS CredentialId,
                user_id AS UserId,
                provider AS Provider,
                secret_hash AS SecretHash,
                created_at AS CreatedAt,
                last_used_at AS LastUsedAt
            FROM fb.id_credential
            WHERE user_id = @UserId
              AND provider = @Provider
            ORDER BY created_at DESC
            LIMIT 1;
            """;

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        var command = new CommandDefinition(
            sql,
            new { UserId = userId, Provider = AuthConstants.PasswordProvider },
            cancellationToken: cancellationToken);

        return await connection.QuerySingleOrDefaultAsync<UserCredential>(command);
    }

    public async Task MarkUsedAsync(
        DbConnection connection,
        DbTransaction transaction,
        long credentialId,
        CancellationToken cancellationToken)
    {
        const string sql = """
            UPDATE fb.id_credential
            SET last_used_at = now()
            WHERE credential_id = @CredentialId;
            """;

        var command = new CommandDefinition(sql, new { CredentialId = credentialId }, transaction, cancellationToken: cancellationToken);
        await connection.ExecuteAsync(command);
    }
}

public interface IVerificationRepository
{
    Task InsertEmailVerificationAsync(
        DbConnection connection,
        DbTransaction transaction,
        long verificationId,
        long userId,
        string tokenHash,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken);

    Task<long?> FindValidEmailVerificationIdAsync(
        DbConnection connection,
        DbTransaction transaction,
        long userId,
        string tokenHash,
        DateTimeOffset now,
        CancellationToken cancellationToken);

    Task MarkUsedAsync(
        DbConnection connection,
        DbTransaction transaction,
        long verificationId,
        CancellationToken cancellationToken);
}

public sealed class VerificationRepository : IVerificationRepository
{
    public async Task InsertEmailVerificationAsync(
        DbConnection connection,
        DbTransaction transaction,
        long verificationId,
        long userId,
        string tokenHash,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO fb.id_verification (verification_id, user_id, type, token_hash, expires_at)
            VALUES (@VerificationId, @UserId, @Type, @TokenHash, @ExpiresAt);
            """;

        var parameters = new
        {
            VerificationId = verificationId,
            UserId = userId,
            Type = AuthConstants.EmailVerificationType,
            TokenHash = tokenHash,
            ExpiresAt = expiresAt
        };

        var command = new CommandDefinition(sql, parameters, transaction, cancellationToken: cancellationToken);
        await connection.ExecuteAsync(command);
    }

    public async Task<long?> FindValidEmailVerificationIdAsync(
        DbConnection connection,
        DbTransaction transaction,
        long userId,
        string tokenHash,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT verification_id
            FROM fb.id_verification
            WHERE user_id = @UserId
              AND type = @Type
              AND token_hash = @TokenHash
              AND is_used = false
              AND expires_at > @Now
            ORDER BY created_at DESC
            LIMIT 1;
            """;

        var parameters = new
        {
            UserId = userId,
            Type = AuthConstants.EmailVerificationType,
            TokenHash = tokenHash,
            Now = now
        };

        var command = new CommandDefinition(sql, parameters, transaction, cancellationToken: cancellationToken);
        return await connection.ExecuteScalarAsync<long?>(command);
    }

    public async Task MarkUsedAsync(
        DbConnection connection,
        DbTransaction transaction,
        long verificationId,
        CancellationToken cancellationToken)
    {
        const string sql = """
            UPDATE fb.id_verification
            SET is_used = true
            WHERE verification_id = @VerificationId;
            """;

        var command = new CommandDefinition(sql, new { VerificationId = verificationId }, transaction, cancellationToken: cancellationToken);
        await connection.ExecuteAsync(command);
    }
}

public interface ISessionRepository
{
    Task InsertAsync(
        DbConnection connection,
        DbTransaction transaction,
        long sessionId,
        long userId,
        string refreshToken,
        ClientMetadata metadata,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken);
}

public sealed class SessionRepository : ISessionRepository
{
    public async Task InsertAsync(
        DbConnection connection,
        DbTransaction transaction,
        long sessionId,
        long userId,
        string refreshToken,
        ClientMetadata metadata,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO fb.id_session (
                session_id,
                user_id,
                refresh_token,
                device_name,
                os,
                browser,
                ip_address,
                expires_at)
            VALUES (
                @SessionId,
                @UserId,
                @RefreshToken,
                @DeviceName,
                @Os,
                @Browser,
                @IpAddress,
                @ExpiresAt);
            """;

        var parameters = new
        {
            SessionId = sessionId,
            UserId = userId,
            RefreshToken = refreshToken,
            metadata.DeviceName,
            metadata.Os,
            metadata.Browser,
            metadata.IpAddress,
            ExpiresAt = expiresAt
        };

        var command = new CommandDefinition(sql, parameters, transaction, cancellationToken: cancellationToken);
        await connection.ExecuteAsync(command);
    }
}

public interface IAuditLogRepository
{
    Task InsertAsync(
        DbConnection connection,
        DbTransaction transaction,
        long auditId,
        long? userId,
        string action,
        ClientMetadata metadata,
        object data,
        CancellationToken cancellationToken);
}

public sealed class AuditLogRepository : IAuditLogRepository
{
    public async Task InsertAsync(
        DbConnection connection,
        DbTransaction transaction,
        long auditId,
        long? userId,
        string action,
        ClientMetadata metadata,
        object data,
        CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO fb.id_audit_log (
                audit_id,
                user_id,
                action,
                ip_address,
                user_agent,
                data)
            VALUES (
                @AuditId,
                @UserId,
                @Action,
                @IpAddress,
                @UserAgent,
                @Data::jsonb);
            """;

        var parameters = new
        {
            AuditId = auditId,
            UserId = userId,
            Action = action,
            metadata.IpAddress,
            metadata.UserAgent,
            Data = JsonSerializer.Serialize(data, new JsonSerializerOptions(JsonSerializerDefaults.Web))
        };

        var command = new CommandDefinition(sql, parameters, transaction, cancellationToken: cancellationToken);
        await connection.ExecuteAsync(command);
    }
}
