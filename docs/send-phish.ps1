# send-phish.ps1
# Sends the phishing lure email to alice.smith@corpsso.local via Mailpit.
# Usage: .\docs\send-phish.ps1 -LureUrl "https://login.evil-corpsso.com/XXXXXXXX"
#
# The visible link text shows the legitimate CorpSSO domain — the actual href
# points to the Evilginx lure URL. This mirrors real-world phishing technique.

param(
    [Parameter(Mandatory = $true)]
    [string]$LureUrl
)

$mailFile = "$env:TEMP\aitm-lab-mail.txt"

@"
From: IT Security <it-security@corpsso.local>
To: Alice Smith <alice.smith@corpsso.local>
Subject: Urgent: Mandatory Password Reset Required
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif;font-size:14px;color:#222;">
  <p>Dear Alice,</p>
  <p>As part of our quarterly security review, all employees are required
  to verify their credentials by <strong>17:00 today</strong>.</p>
  <p>Please click the button below to re-authenticate:</p>
  <p>
    <a href="$LureUrl"
       style="background:#0057b8;color:#fff;padding:10px 20px;
              text-decoration:none;border-radius:4px;display:inline-block;">
      Verify My Identity
    </a>
  </p>
  <p>Failure to complete this step will result in your account being
  temporarily suspended.</p>
  <p>Kind regards,<br>
  <strong>IT Security Team</strong><br>
  CorpSSO &mdash; Identity &amp; Access Management</p>
  <hr style="border:none;border-top:1px solid #ddd;margin-top:20px;">
  <p style="font-size:11px;color:#888;">
    This is an automated message. Do not reply directly to this email.<br>
    &copy; 2026 CorpSSO Ltd. All rights reserved.
  </p>
</body>
</html>
"@ | Out-File $mailFile -Encoding ascii -NoNewline

curl.exe --url smtp://localhost:1025 `
    --mail-from "it-security@corpsso.local" `
    --mail-rcpt "alice.smith@corpsso.local" `
    --upload-file $mailFile

Remove-Item $mailFile
