using HotChocolate;

namespace fakebookAuth;

public sealed class Query
{
    public string Health() => "ok";
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
}
