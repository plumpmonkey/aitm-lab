#!/usr/bin/env bash
# send-phish.sh
# Sends the phishing lure email to alice.smith@corpsso.local via Mailpit.
# Usage: ./docs/send-phish.sh "https://login.evil-corpsso.com/XXXXXXXX"
#
# The visible button links to the Evilginx lure URL — the evil domain is never
# shown in the email body, mirroring real-world phishing technique.

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <lure-url>"
    echo "  Example: $0 \"https://login.evil-corpsso.com/XXXXXXXX\""
    exit 1
fi

LURE_URL="$1"
MAIL_FILE="$(mktemp /tmp/aitm-lab-mail.XXXXXX)"

cat > "$MAIL_FILE" << EOF
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
    <a href="${LURE_URL}"
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
EOF

curl --url smtp://localhost:1025 \
    --mail-from "it-security@corpsso.local" \
    --mail-rcpt "alice.smith@corpsso.local" \
    --upload-file "$MAIL_FILE"

rm "$MAIL_FILE"
