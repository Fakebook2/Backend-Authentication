using HotChocolate;

namespace fakebookAuth;

public sealed class Query
{
    public string Health() => "ok";

    public Task<UserType> Me(
        [Service] IAuthService authService,
        CancellationToken cancellationToken) =>
        authService.MeAsync(cancellationToken);

    public Task<IReadOnlyList<SessionType>> MySessions(
        [Service] IAuthService authService,
        CancellationToken cancellationToken) =>
        authService.MySessionsAsync(cancellationToken);
}

public sealed class AuthMutations
{
    public Task<RegisterPayload> Register(
        RegisterInput input,
        [Service] IAuthService authService,
        CancellationToken cancellationToken) =>
        authService.RegisterAsync(input, cancellationToken);

    public Task<VerifyEmailPayload> VerifyEmail(
        VerifyEmailInput input,
        [Service] IAuthService authService,
        CancellationToken cancellationToken) =>
        authService.VerifyEmailAsync(input, cancellationToken);

    public Task<LoginPayload> Login(
        LoginInput input,
        [Service] IAuthService authService,
        CancellationToken cancellationToken) =>
        authService.LoginAsync(input, cancellationToken);

    public Task<LoginPayload> RefreshToken(
        RefreshTokenInput input,
        [Service] IAuthService authService,
        CancellationToken cancellationToken) =>
        authService.RefreshTokenAsync(input, cancellationToken);

    public Task<AuthActionPayload> Logout(
        LogoutInput input,
        [Service] IAuthService authService,
        CancellationToken cancellationToken) =>
        authService.LogoutAsync(input, cancellationToken);

    public Task<AuthActionPayload> LogoutAll(
        [Service] IAuthService authService,
        CancellationToken cancellationToken) =>
        authService.LogoutAllAsync(cancellationToken);

    public Task<AuthActionPayload> ResendEmailVerification(
        ResendEmailVerificationInput input,
        [Service] IAuthService authService,
        CancellationToken cancellationToken) =>
        authService.ResendEmailVerificationAsync(input, cancellationToken);

    public Task<AuthActionPayload> RequestPasswordReset(
        RequestPasswordResetInput input,
        [Service] IAuthService authService,
        CancellationToken cancellationToken) =>
        authService.RequestPasswordResetAsync(input, cancellationToken);

    public Task<AuthActionPayload> ResetPassword(
        ResetPasswordInput input,
        [Service] IAuthService authService,
        CancellationToken cancellationToken) =>
        authService.ResetPasswordAsync(input, cancellationToken);
}
