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
        if (!_options.Enabled)
        {
            return;
        }

        cancellationToken.ThrowIfCancellationRequested();

        using var message = new MailMessage
        {
            From = new MailAddress(_options.FromEmail, _options.FromName),
            Subject = "Verify your Fakebook account",
            Body = BuildVerificationBody(displayName, otp),
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
}
