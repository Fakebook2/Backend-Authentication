using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Options;

namespace fakebookAuth;

public interface IEmailSender
{
    Task SendVerificationOtpAsync(
        string email,
        string displayName,
        string otp,
        CancellationToken cancellationToken);

    Task SendPasswordResetOtpAsync(
        string email,
        string displayName,
        string otp,
        CancellationToken cancellationToken);
}

public sealed class SmtpEmailSender(IOptions<SmtpOptions> options) : IEmailSender
{
    private readonly SmtpOptions _options = options.Value;

    public async Task SendVerificationOtpAsync(
        string email,
        string displayName,
        string otp,
        CancellationToken cancellationToken)
    {
        await SendOtpAsync(
            email,
            displayName,
            "Verify your Fakebook account",
            BuildVerificationBody(displayName, otp),
            cancellationToken);
    }

    public async Task SendPasswordResetOtpAsync(
        string email,
        string displayName,
        string otp,
        CancellationToken cancellationToken)
    {
        await SendOtpAsync(
            email,
            displayName,
            "Reset your Fakebook password",
            BuildPasswordResetBody(displayName, otp),
            cancellationToken);
    }

    private async Task SendOtpAsync(
        string email,
        string displayName,
        string subject,
        string body,
        CancellationToken cancellationToken)
    {
        if (!_options.Enabled)
        {
            return;
        }

        cancellationToken.ThrowIfCancellationRequested();

        using var message = new MailMessage
        {
            From = new MailAddress(_options.FromEmail, _options.FromName),
            Subject = subject,
            Body = body,
            IsBodyHtml = false
        };

        message.To.Add(new MailAddress(email, displayName));

        using var client = new SmtpClient(_options.Host, _options.Port)
        {
            EnableSsl = _options.EnableSsl,
            Credentials = new NetworkCredential(_options.Username, _options.Password),
            DeliveryMethod = SmtpDeliveryMethod.Network
        };

        await client.SendMailAsync(message, cancellationToken);
    }

    private static string BuildVerificationBody(string displayName, string otp) =>
        $"""
        Hi {displayName},

        Your Fakebook verification code is:

        {otp}

        This code expires in 15 minutes. If you did not create a Fakebook account, you can ignore this email.

        Fakebook
        """;

    private static string BuildPasswordResetBody(string displayName, string otp) =>
        $"""
        Hi {displayName},

        Your Fakebook password reset code is:

        {otp}

        This code expires in 15 minutes. If you did not request a password reset, you can ignore this email.

        Fakebook
        """;
}
