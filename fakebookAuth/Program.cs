using Dapper;
using Npgsql;

namespace fakebookAuth;

public static class Program
{
    public static void Main(string[] args)
    {
        DefaultTypeMap.MatchNamesWithUnderscores = true;

        var builder = WebApplication.CreateBuilder(args);

        var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            connectionString = builder.Configuration["POSTGRES_CONNECTION_STRING"];
        }

        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException(
                "Database connection string is required. Configure ConnectionStrings:DefaultConnection or POSTGRES_CONNECTION_STRING.");
        }

        builder.Services
            .AddOptions<JwtOptions>()
            .Bind(builder.Configuration.GetSection(JwtOptions.SectionName))
            .Validate(options => !string.IsNullOrWhiteSpace(options.SigningKey), "Jwt:SigningKey is required.")
            .Validate(options => options.SigningKeyBytes >= 32, "Jwt:SigningKey must be at least 32 bytes.")
            .Validate(options => options.AccessTokenMinutes > 0, "Jwt:AccessTokenMinutes must be greater than zero.")
            .ValidateOnStart();

        builder.Services
            .AddOptions<AuthOptions>()
            .Bind(builder.Configuration.GetSection(AuthOptions.SectionName))
            .Validate(options => options.RefreshTokenDays > 0, "Auth:RefreshTokenDays must be greater than zero.")
            .Validate(options => options.EmailVerificationMinutes > 0, "Auth:EmailVerificationMinutes must be greater than zero.")
            .Validate(options => options.PasswordResetMinutes > 0, "Auth:PasswordResetMinutes must be greater than zero.")
            .Validate(options => options.OtpCooldownSeconds >= 0, "Auth:OtpCooldownSeconds must be greater than or equal to zero.")
            .ValidateOnStart();

        builder.Services
            .AddOptions<SmtpOptions>()
            .Bind(builder.Configuration.GetSection(SmtpOptions.SectionName))
            .Validate(options => !options.Enabled || options.IsConfigured, "SMTP must be fully configured when Smtp:Enabled is true.")
            .ValidateOnStart();

        builder.Services
            .AddOptions<SnowflakeOptions>()
            .Bind(builder.Configuration.GetSection(SnowflakeOptions.SectionName))
            .Validate(options => options.WorkerId is >= 0 and <= 1023, "Snowflake:WorkerId must be between 0 and 1023.")
            .ValidateOnStart();

        builder.Services.AddSingleton(_ => NpgsqlDataSource.Create(connectionString));
        builder.Services.AddHttpContextAccessor();

        builder.Services.AddSingleton<ISnowflakeIdGenerator, SnowflakeIdGenerator>();
        builder.Services.AddSingleton<IPasswordHasher, BCryptPasswordHasher>();
        builder.Services.AddSingleton<ITokenService, TokenService>();
        builder.Services.AddSingleton<IEmailSender, SmtpEmailSender>();

        builder.Services.AddScoped<IUserRepository, UserRepository>();
        builder.Services.AddScoped<ICredentialRepository, CredentialRepository>();
        builder.Services.AddScoped<IVerificationRepository, VerificationRepository>();
        builder.Services.AddScoped<ISessionRepository, SessionRepository>();
        builder.Services.AddScoped<IAuditLogRepository, AuditLogRepository>();
        builder.Services.AddScoped<IAuthService, AuthService>();

        builder.Services
            .AddGraphQLServer()
            .ModifyRequestOptions(options => options.IncludeExceptionDetails = builder.Environment.IsDevelopment())
            .AddQueryType<Query>()
            .AddMutationType<AuthMutations>()
            .AddType<DateType>();

        var app = builder.Build();

        app.MapGraphQL();
        app.MapGet("/", () => Results.Redirect("/graphql"));

        app.Run();
    }
}
