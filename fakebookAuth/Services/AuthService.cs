using System.ComponentModel.DataAnnotations;
using Npgsql;

namespace fakebookAuth;

public interface IAuthService
{
    Task<RegisterPayload> RegisterAsync(RegisterInput input, CancellationToken cancellationToken);
    Task<VerifyEmailPayload> VerifyEmailAsync(VerifyEmailInput input, CancellationToken cancellationToken);
    Task<LoginPayload> LoginAsync(LoginInput input, CancellationToken cancellationToken);
    Task<LoginPayload> RefreshTokenAsync(RefreshTokenInput input, CancellationToken cancellationToken);
    Task<AuthActionPayload> LogoutAsync(LogoutInput input, CancellationToken cancellationToken);
    Task<AuthActionPayload> LogoutAllAsync(CancellationToken cancellationToken);
    Task<IReadOnlyList<SessionType>> MySessionsAsync(CancellationToken cancellationToken);
    Task<AuthActionPayload> ResendEmailVerificationAsync(ResendEmailVerificationInput input, CancellationToken cancellationToken);
    Task<AuthActionPayload> RequestPasswordResetAsync(RequestPasswordResetInput input, CancellationToken cancellationToken);
    Task<AuthActionPayload> ResetPasswordAsync(ResetPasswordInput input, CancellationToken cancellationToken);
    Task<UserType> MeAsync(CancellationToken cancellationToken);
}

public sealed class AuthService(
    NpgsqlDataSource dataSource,
    IUserRepository users,
    ICredentialRepository credentials,
    IVerificationRepository verifications,
    ISessionRepository sessions,
    IAuditLogRepository auditLogs,
    IPasswordHasher passwordHasher,
    ITokenService tokenService,
    IEmailSender emailSender,
    ISnowflakeIdGenerator ids,
    IHttpContextAccessor httpContextAccessor,
    Microsoft.Extensions.Options.IOptions<AuthOptions> authOptions,
    Microsoft.Extensions.Options.IOptions<SmtpOptions> smtpOptions) : IAuthService
{
    private readonly AuthOptions _authOptions = authOptions.Value;
    private readonly SmtpOptions _smtpOptions = smtpOptions.Value;

    public async Task<RegisterPayload> RegisterAsync(RegisterInput input, CancellationToken cancellationToken)
    {
        var register = NormalizeAndValidate(input);

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        try
        {
            if (await users.IdentifierExistsAsync(
                    connection,
                    transaction,
                    register.Email,
                    register.Username,
                    cancellationToken))
            {
                throw GraphQlError("Email or username already exists.", "IDENTIFIER_EXISTS");
            }

            var userId = ids.NewId();
            await users.InsertAsync(
                connection,
                transaction,
                new IdentityUser
                {
                    UserId = userId,
                    Email = register.Email,
                    Username = register.Username,
                    Dob = register.Dob,
                    DisplayName = register.DisplayName,
                    Status = AuthConstants.StatusUnverified
                },
                cancellationToken);

            await credentials.InsertPasswordCredentialAsync(
                connection,
                transaction,
                ids.NewId(),
                userId,
                passwordHasher.Hash(register.Password),
                cancellationToken);

            var otp = OtpGenerator.SixDigitCode();
            await verifications.InsertEmailVerificationAsync(
                connection,
                transaction,
                ids.NewId(),
                userId,
                TokenHashing.Sha256Hex(otp),
                DateTimeOffset.UtcNow.AddMinutes(_authOptions.EmailVerificationMinutes),
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);

            if (_smtpOptions.Enabled)
            {
                await emailSender.SendVerificationOtpAsync(
                    register.Email,
                    register.DisplayName,
                    otp,
                    cancellationToken);

                return new RegisterPayload(true, "Registration successful. Please check your email for the verification code.");
            }

            return new RegisterPayload(true, "Registration successful. Email delivery is disabled; verify manually before signing in.");
        }
        catch (GraphQLException)
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
        catch (PostgresException exception) when (exception.SqlState == PostgresErrorCodes.UniqueViolation)
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw GraphQlError("Email or username already exists.", "IDENTIFIER_EXISTS");
        }
        catch
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
    }

    public async Task<VerifyEmailPayload> VerifyEmailAsync(VerifyEmailInput input, CancellationToken cancellationToken)
    {
        var identifier = NormalizeIdentifier(input.Identifier);
        var otp = NormalizeOtp(input.Otp);

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        try
        {
            var user = await users.FindByIdentifierAsync(connection, transaction, identifier, cancellationToken);
            if (user is null)
            {
                throw GraphQlError("Verification code is invalid or expired.", "INVALID_OR_EXPIRED_VERIFICATION_CODE");
            }

            if (user.Status == AuthConstants.StatusActive)
            {
                await transaction.CommitAsync(cancellationToken);
                return new VerifyEmailPayload(true, "Email is already verified.");
            }

            if (user.Status is AuthConstants.StatusDisabled or AuthConstants.StatusDeleted)
            {
                throw GraphQlError("This account has been disabled or deleted.", "ACCOUNT_UNAVAILABLE");
            }

            var verificationId = await verifications.FindValidEmailVerificationIdAsync(
                connection,
                transaction,
                user.UserId,
                TokenHashing.Sha256Hex(otp),
                DateTimeOffset.UtcNow,
                cancellationToken);

            if (verificationId is null)
            {
                throw GraphQlError("Verification code is invalid or expired.", "INVALID_OR_EXPIRED_VERIFICATION_CODE");
            }

            await users.ActivateAsync(connection, transaction, user.UserId, cancellationToken);
            await verifications.MarkUsedAsync(connection, transaction, verificationId.Value, cancellationToken);

            await transaction.CommitAsync(cancellationToken);

            return new VerifyEmailPayload(true, "Email verified successfully.");
        }
        catch (GraphQLException)
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
        catch
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
    }

    public async Task<LoginPayload> LoginAsync(LoginInput input, CancellationToken cancellationToken)
    {
        var identifier = NormalizeIdentifier(input.Identifier);
        if (string.IsNullOrWhiteSpace(identifier) || string.IsNullOrWhiteSpace(input.Password))
        {
            throw InvalidCredentials();
        }

        var user = await users.FindByIdentifierAsync(identifier, cancellationToken);
        if (user is null)
        {
            throw InvalidCredentials();
        }

        if (user.Status == AuthConstants.StatusUnverified)
        {
            throw GraphQlError("Please verify your email before signing in.", "EMAIL_UNVERIFIED");
        }

        if (user.Status is AuthConstants.StatusDisabled or AuthConstants.StatusDeleted)
        {
            throw GraphQlError("This account has been disabled or deleted.", "ACCOUNT_UNAVAILABLE");
        }

        var credential = await credentials.FindPasswordCredentialAsync(user.UserId, cancellationToken);
        if (credential?.SecretHash is null || !passwordHasher.Verify(input.Password, credential.SecretHash))
        {
            throw InvalidCredentials();
        }

        var refreshToken = tokenService.CreateRefreshToken();
        var refreshExpiresAt = DateTimeOffset.UtcNow.AddDays(_authOptions.RefreshTokenDays);
        var metadata = ClientMetadata.From(httpContextAccessor.HttpContext);
        var sessionId = ids.NewId();

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        try
        {
            await sessions.InsertAsync(
                connection,
                transaction,
                sessionId,
                user.UserId,
                TokenHashing.Sha256Hex(refreshToken),
                metadata,
                refreshExpiresAt,
                cancellationToken);

            await credentials.MarkUsedAsync(connection, transaction, credential.CredentialId, cancellationToken);

            await auditLogs.InsertAsync(
                connection,
                transaction,
                ids.NewId(),
                user.UserId,
                "LOGIN_SUCCESS",
                metadata,
                new { sessionId },
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);
        }
        catch
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }

        return new LoginPayload(
            tokenService.CreateAccessToken(user, sessionId),
            refreshToken,
            refreshExpiresAt,
            user.ToGraphQl());
    }

    public async Task<LoginPayload> RefreshTokenAsync(RefreshTokenInput input, CancellationToken cancellationToken)
    {
        var refreshToken = NormalizeRefreshToken(input.RefreshToken);
        var refreshTokenHash = TokenHashing.Sha256Hex(refreshToken);
        var now = DateTimeOffset.UtcNow;

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        try
        {
            var session = await sessions.FindActiveByRefreshTokenHashAsync(
                connection,
                transaction,
                refreshTokenHash,
                now,
                cancellationToken);

            if (session is null)
            {
                throw GraphQlError("Refresh token is invalid or expired.", "INVALID_REFRESH_TOKEN");
            }

            var user = await users.FindByIdAsync(connection, transaction, session.UserId, cancellationToken);
            if (user is null || user.Status is AuthConstants.StatusDisabled or AuthConstants.StatusDeleted)
            {
                await sessions.RevokeAsync(connection, transaction, session.SessionId, cancellationToken);
                throw GraphQlError("This account has been disabled or deleted.", "ACCOUNT_UNAVAILABLE");
            }

            if (user.Status == AuthConstants.StatusUnverified)
            {
                throw GraphQlError("Please verify your email before signing in.", "EMAIL_UNVERIFIED");
            }

            var newRefreshToken = tokenService.CreateRefreshToken();
            var refreshExpiresAt = now.AddDays(_authOptions.RefreshTokenDays);
            var metadata = ClientMetadata.From(httpContextAccessor.HttpContext);

            await sessions.RotateRefreshTokenAsync(
                connection,
                transaction,
                session.SessionId,
                TokenHashing.Sha256Hex(newRefreshToken),
                refreshExpiresAt,
                cancellationToken);

            await auditLogs.InsertAsync(
                connection,
                transaction,
                ids.NewId(),
                user.UserId,
                "REFRESH_TOKEN_ROTATED",
                metadata,
                new { session.SessionId },
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);

            return new LoginPayload(
                tokenService.CreateAccessToken(user, session.SessionId),
                newRefreshToken,
                refreshExpiresAt,
                user.ToGraphQl());
        }
        catch (GraphQLException)
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
        catch
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
    }

    public async Task<AuthActionPayload> LogoutAsync(LogoutInput input, CancellationToken cancellationToken)
    {
        var refreshToken = input.RefreshToken.Trim();
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            return new AuthActionPayload(true, "Logged out.");
        }

        var refreshTokenHash = TokenHashing.Sha256Hex(refreshToken);
        var metadata = ClientMetadata.From(httpContextAccessor.HttpContext);

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        try
        {
            var session = await sessions.FindActiveByRefreshTokenHashAsync(
                connection,
                transaction,
                refreshTokenHash,
                DateTimeOffset.UtcNow,
                cancellationToken);

            if (session is not null)
            {
                await sessions.RevokeAsync(connection, transaction, session.SessionId, cancellationToken);
                await auditLogs.InsertAsync(
                    connection,
                    transaction,
                    ids.NewId(),
                    session.UserId,
                    "LOGOUT",
                    metadata,
                    new { session.SessionId },
                    cancellationToken);
            }

            await transaction.CommitAsync(cancellationToken);
            return new AuthActionPayload(true, "Logged out.");
        }
        catch
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
    }

    public async Task<AuthActionPayload> LogoutAllAsync(CancellationToken cancellationToken)
    {
        var (user, principal) = await GetCurrentUserAsync(cancellationToken);
        var metadata = ClientMetadata.From(httpContextAccessor.HttpContext);

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        try
        {
            await sessions.RevokeAllByUserIdAsync(connection, transaction, user.UserId, cancellationToken);
            await auditLogs.InsertAsync(
                connection,
                transaction,
                ids.NewId(),
                user.UserId,
                "LOGOUT_ALL",
                metadata,
                new { principal.SessionId },
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);
            return new AuthActionPayload(true, "All sessions have been logged out.");
        }
        catch
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
    }

    public async Task<IReadOnlyList<SessionType>> MySessionsAsync(CancellationToken cancellationToken)
    {
        var (user, principal) = await GetCurrentUserAsync(cancellationToken);
        var activeSessions = await sessions.ListActiveByUserIdAsync(
            user.UserId,
            DateTimeOffset.UtcNow,
            cancellationToken);

        return activeSessions
            .Select(session => session.ToGraphQl(principal.SessionId))
            .ToList();
    }

    public async Task<AuthActionPayload> ResendEmailVerificationAsync(
        ResendEmailVerificationInput input,
        CancellationToken cancellationToken)
    {
        var identifier = NormalizeIdentifier(input.Identifier);

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        try
        {
            var user = await users.FindByIdentifierAsync(connection, transaction, identifier, cancellationToken);
            if (user is null)
            {
                throw GraphQlError("Account was not found.", "ACCOUNT_NOT_FOUND");
            }

            if (user.Status == AuthConstants.StatusActive)
            {
                await transaction.CommitAsync(cancellationToken);
                return new AuthActionPayload(true, "Email is already verified.");
            }

            if (user.Status is AuthConstants.StatusDisabled or AuthConstants.StatusDeleted)
            {
                throw GraphQlError("This account has been disabled or deleted.", "ACCOUNT_UNAVAILABLE");
            }

            await EnsureOtpCooldownAsync(
                connection,
                transaction,
                user.UserId,
                AuthConstants.EmailVerificationType,
                cancellationToken);

            await verifications.MarkUnusedByUserAndTypeAsUsedAsync(
                connection,
                transaction,
                user.UserId,
                AuthConstants.EmailVerificationType,
                cancellationToken);

            var otp = OtpGenerator.SixDigitCode();
            await verifications.InsertVerificationAsync(
                connection,
                transaction,
                ids.NewId(),
                user.UserId,
                AuthConstants.EmailVerificationType,
                TokenHashing.Sha256Hex(otp),
                DateTimeOffset.UtcNow.AddMinutes(_authOptions.EmailVerificationMinutes),
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);

            await emailSender.SendVerificationOtpAsync(user.Email, user.DisplayName, otp, cancellationToken);
            return new AuthActionPayload(true, "Verification code sent. Please check your email.");
        }
        catch (GraphQLException)
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
        catch
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
    }

    public async Task<AuthActionPayload> RequestPasswordResetAsync(
        RequestPasswordResetInput input,
        CancellationToken cancellationToken)
    {
        var identifier = NormalizeIdentifier(input.Identifier);
        IdentityUser? userToEmail = null;
        string? otpToEmail = null;

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        try
        {
            var user = await users.FindByIdentifierAsync(connection, transaction, identifier, cancellationToken);
            if (user is not null &&
                user.Status == AuthConstants.StatusActive)
            {
                await EnsureOtpCooldownAsync(
                    connection,
                    transaction,
                    user.UserId,
                    AuthConstants.PasswordResetVerificationType,
                    cancellationToken);

                await verifications.MarkUnusedByUserAndTypeAsUsedAsync(
                    connection,
                    transaction,
                    user.UserId,
                    AuthConstants.PasswordResetVerificationType,
                    cancellationToken);

                var otp = OtpGenerator.SixDigitCode();
                await verifications.InsertVerificationAsync(
                    connection,
                    transaction,
                    ids.NewId(),
                    user.UserId,
                    AuthConstants.PasswordResetVerificationType,
                    TokenHashing.Sha256Hex(otp),
                    DateTimeOffset.UtcNow.AddMinutes(_authOptions.PasswordResetMinutes),
                    cancellationToken);

                userToEmail = user;
                otpToEmail = otp;
            }

            await transaction.CommitAsync(cancellationToken);
        }
        catch (GraphQLException)
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
        catch
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }

        if (userToEmail is not null && otpToEmail is not null)
        {
            await emailSender.SendPasswordResetOtpAsync(
                userToEmail.Email,
                userToEmail.DisplayName,
                otpToEmail,
                cancellationToken);
        }

        return new AuthActionPayload(true, "If the account exists, a password reset code has been sent.");
    }

    public async Task<AuthActionPayload> ResetPasswordAsync(
        ResetPasswordInput input,
        CancellationToken cancellationToken)
    {
        var identifier = NormalizeIdentifier(input.Identifier);
        var otp = NormalizeOtp(input.Otp);
        ValidatePassword(input.NewPassword);

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);

        try
        {
            var user = await users.FindByIdentifierAsync(connection, transaction, identifier, cancellationToken);
            if (user is null || user.Status != AuthConstants.StatusActive)
            {
                throw GraphQlError("Password reset code is invalid or expired.", "INVALID_OR_EXPIRED_PASSWORD_RESET_CODE");
            }

            var verificationId = await verifications.FindValidVerificationIdAsync(
                connection,
                transaction,
                user.UserId,
                AuthConstants.PasswordResetVerificationType,
                TokenHashing.Sha256Hex(otp),
                DateTimeOffset.UtcNow,
                cancellationToken);

            if (verificationId is null)
            {
                throw GraphQlError("Password reset code is invalid or expired.", "INVALID_OR_EXPIRED_PASSWORD_RESET_CODE");
            }

            var secretHash = passwordHasher.Hash(input.NewPassword);
            var updated = await credentials.UpdatePasswordCredentialAsync(
                connection,
                transaction,
                user.UserId,
                secretHash,
                cancellationToken);

            if (updated == 0)
            {
                await credentials.InsertPasswordCredentialAsync(
                    connection,
                    transaction,
                    ids.NewId(),
                    user.UserId,
                    secretHash,
                    cancellationToken);
            }

            await verifications.MarkUsedAsync(connection, transaction, verificationId.Value, cancellationToken);
            await sessions.RevokeAllByUserIdAsync(connection, transaction, user.UserId, cancellationToken);

            await auditLogs.InsertAsync(
                connection,
                transaction,
                ids.NewId(),
                user.UserId,
                "PASSWORD_RESET",
                ClientMetadata.From(httpContextAccessor.HttpContext),
                new { },
                cancellationToken);

            await transaction.CommitAsync(cancellationToken);
            return new AuthActionPayload(true, "Password has been reset.");
        }
        catch (GraphQLException)
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
        catch
        {
            await RollbackQuietlyAsync(transaction, cancellationToken);
            throw;
        }
    }

    public async Task<UserType> MeAsync(CancellationToken cancellationToken)
    {
        var (user, _) = await GetCurrentUserAsync(cancellationToken);
        return user.ToGraphQl();
    }

    private static NormalizedRegisterInput NormalizeAndValidate(RegisterInput input)
    {
        var email = NormalizeIdentifier(input.Email);
        var username = NormalizeIdentifier(input.Username);
        var displayName = input.DisplayName.Trim();

        if (string.IsNullOrWhiteSpace(displayName))
        {
            throw GraphQlError("Display name is required.", "INVALID_DISPLAY_NAME");
        }

        if (!new EmailAddressAttribute().IsValid(email))
        {
            throw GraphQlError("Email is invalid.", "INVALID_EMAIL");
        }

        if (string.IsNullOrWhiteSpace(username))
        {
            throw GraphQlError("Username is required.", "INVALID_USERNAME");
        }

        ValidatePassword(input.Password);

        if (input.Dob > DateOnly.FromDateTime(DateTime.UtcNow))
        {
            throw GraphQlError("Date of birth is invalid.", "INVALID_DOB");
        }

        return new NormalizedRegisterInput(displayName, input.Dob, email, username, input.Password);
    }

    private static string NormalizeIdentifier(string value) => value.Trim().ToLowerInvariant();

    private static string NormalizeRefreshToken(string value)
    {
        var refreshToken = value.Trim();
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            throw GraphQlError("Refresh token is required.", "INVALID_REFRESH_TOKEN");
        }

        return refreshToken;
    }

    private static void ValidatePassword(string password)
    {
        if (password.Length < 8)
        {
            throw GraphQlError("Password must be at least 8 characters long.", "WEAK_PASSWORD");
        }
    }

    private static string NormalizeOtp(string value)
    {
        var otp = value.Trim();
        if (otp.Length != 6 || otp.Any(character => !char.IsDigit(character)))
        {
            throw GraphQlError("Verification code must be 6 digits.", "INVALID_VERIFICATION_CODE");
        }

        return otp;
    }

    private async Task EnsureOtpCooldownAsync(
        System.Data.Common.DbConnection connection,
        System.Data.Common.DbTransaction transaction,
        long userId,
        short type,
        CancellationToken cancellationToken)
    {
        if (_authOptions.OtpCooldownSeconds == 0)
        {
            return;
        }

        var latestCreatedAt = await verifications.FindLatestCreatedAtAsync(
            connection,
            transaction,
            userId,
            type,
            cancellationToken);

        if (latestCreatedAt is null)
        {
            return;
        }

        var nextAllowedAt = latestCreatedAt.Value.AddSeconds(_authOptions.OtpCooldownSeconds);
        if (nextAllowedAt > DateTimeOffset.UtcNow)
        {
            throw GraphQlError("Please wait before requesting another code.", "OTP_COOLDOWN");
        }
    }

    private async Task<(IdentityUser User, AccessTokenPrincipal Principal)> GetCurrentUserAsync(
        CancellationToken cancellationToken)
    {
        var principal = GetCurrentPrincipal();
        var user = await users.FindByIdAsync(principal.UserId, cancellationToken);

        if (user is null)
        {
            throw Unauthenticated();
        }

        if (user.Status == AuthConstants.StatusUnverified)
        {
            throw GraphQlError("Please verify your email before continuing.", "EMAIL_UNVERIFIED");
        }

        if (user.Status is AuthConstants.StatusDisabled or AuthConstants.StatusDeleted)
        {
            throw GraphQlError("This account has been disabled or deleted.", "ACCOUNT_UNAVAILABLE");
        }

        return (user, principal);
    }

    private AccessTokenPrincipal GetCurrentPrincipal()
    {
        var authorization = httpContextAccessor.HttpContext?.Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(authorization) ||
            !authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            throw Unauthenticated();
        }

        var token = authorization["Bearer ".Length..].Trim();
        if (string.IsNullOrWhiteSpace(token) ||
            !tokenService.TryValidateAccessToken(token, out var principal) ||
            principal is null)
        {
            throw Unauthenticated();
        }

        return principal;
    }

    private static async Task RollbackQuietlyAsync(
        System.Data.Common.DbTransaction transaction,
        CancellationToken cancellationToken)
    {
        try
        {
            await transaction.RollbackAsync(cancellationToken);
        }
        catch
        {
            // Original exception is more useful than a rollback failure.
        }
    }

    private static GraphQLException InvalidCredentials() => GraphQlError("Invalid credentials.", "INVALID_CREDENTIALS");

    private static GraphQLException Unauthenticated() => GraphQlError("Authentication is required.", "UNAUTHENTICATED");

    private static GraphQLException GraphQlError(string message, string code) =>
        new(ErrorBuilder.New().SetMessage(message).SetCode(code).Build());

    private sealed record NormalizedRegisterInput(
        string DisplayName,
        DateOnly Dob,
        string Email,
        string Username,
        string Password);
}
