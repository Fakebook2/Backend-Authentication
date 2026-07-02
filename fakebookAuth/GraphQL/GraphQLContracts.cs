using HotChocolate.Types;

namespace fakebookAuth;

public sealed record RegisterInput(
    string DisplayName,
    [property: GraphQLType(typeof(DateType))]
    DateOnly Dob,
    string Email,
    string Username,
    string Password);

public sealed record RegisterPayload(bool Success, string? Message);

public sealed record VerifyEmailInput(string Identifier, string Otp);

public sealed record VerifyEmailPayload(bool Success, string? Message);

public sealed record LoginInput(string Identifier, string Password);

public sealed record LoginPayload(
    string AccessToken,
    string RefreshToken,
    [property: GraphQLType(typeof(DateTimeType))]
    DateTimeOffset RefreshTokenExpiresAt,
    UserType User);

public sealed record UserType(
    long UserId,
    string Email,
    string Username,
    [property: GraphQLType(typeof(DateType))]
    DateOnly? Dob,
    string DisplayName,
    short Status);
