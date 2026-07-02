using System.ComponentModel.DataAnnotations;
using Npgsql;

namespace fakebookAuth;

public interface IAuthService
{
    Task<RegisterPayload> RegisterAsync(RegisterInput input, CancellationToken cancellationToken);
    Task<VerifyEmailPayload> VerifyEmailAsync(VerifyEmailInput input, CancellationToken cancellationToken);
    Task<LoginPayload> LoginAsync(LoginInput input, CancellationToken cancellationToken);
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
                DateTimeOffset.UtcNow.AddMinutes(15),
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
                refreshToken,
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
            tokenService.CreateAccessToken(user),
            refreshToken,
            refreshExpiresAt,
            user.ToGraphQl());
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

        if (input.Password.Length < 8)
        {
            throw GraphQlError("Password must be at least 8 characters long.", "WEAK_PASSWORD");
        }

        if (input.Dob > DateOnly.FromDateTime(DateTime.UtcNow))
        {
            throw GraphQlError("Date of birth is invalid.", "INVALID_DOB");
        }

        return new NormalizedRegisterInput(displayName, input.Dob, email, username, input.Password);
    }

    private static string NormalizeIdentifier(string value) => value.Trim().ToLowerInvariant();

    private static string NormalizeOtp(string value)
    {
        var otp = value.Trim();
        if (otp.Length != 6 || otp.Any(character => !char.IsDigit(character)))
        {
            throw GraphQlError("Verification code must be 6 digits.", "INVALID_VERIFICATION_CODE");
        }

        return otp;
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

    private static GraphQLException GraphQlError(string message, string code) =>
        new(ErrorBuilder.New().SetMessage(message).SetCode(code).Build());

    private sealed record NormalizedRegisterInput(
        string DisplayName,
        DateOnly Dob,
        string Email,
        string Username,
        string Password);
}
