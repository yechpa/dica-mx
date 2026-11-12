#!/usr/bin/env python3
"""
bdika_mx.py - DICA MX tool (Diagnostic d'Infrastructure de Courrier Applicatif)

Automates the flow described in "How to start MX Record Check.pdf":
  1) DNS reconnaissance (real MX lookup for the client domain)
  2) DNS posture check (SPF/DMARC) for the tested domain and the spoofed
     domain -- passive, read-only, no SMTP connection, gives context for
     interpreting the active tests below
  3) Unauthenticated send test
  4) Spoofing test
  5) Open mail relay test
  6) Optional QR-code awareness test (--qr-url; generic template, no
     third-party brand impersonation)
  7) SMTP code interpretation (250 = accepted, 550/55x = relay refused =
     good sign)
  8) Report generation, ready to paste into the end-of-engagement email

AUTHORIZED USE ONLY: this script sends real raw SMTP messages (including a
spoofed "From") to the target domain's mail server -- never use it outside
a signed client mandate.

Example:
    python bdika_mx.py client-domain.com \\
        --internal-email firstname.lastname@client-domain.com \\
        --relay-test-email control.integrity@gmail.com \\
        --spoof-from support@external-provider.example \\
        --confirm-authorized

Without --confirm-authorized, the script asks for interactive confirmation
before sending anything.
"""

import argparse
import io
import smtplib
import socket
import sys
import json
import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from pathlib import Path

# Windows console defaults to cp1252 -> can't display some characters
# (accents, bullets). Force stdout/stderr to UTF-8 when possible, and fall
# back to a silent replacement otherwise (never crash on a simple print).
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

try:
    import dns.resolver  # pip install dnspython
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False

try:
    import qrcode  # pip install "qrcode[pil]"
    HAVE_QRCODE = True
except ImportError:
    HAVE_QRCODE = False


# --------------------------------------------------------------------------
# Reconnaissance: find the target domain's MX records
# --------------------------------------------------------------------------

def lookup_mx(domain):
    """Returns a sorted list of (priority, hostname), via dnspython when
    available, otherwise via socket.getaddrinfo as a last resort (less
    reliable for pure MX lookups, so dnspython is strongly recommended)."""
    if HAVE_DNSPYTHON:
        answers = dns.resolver.resolve(domain, "MX")
        records = sorted(
            [(r.preference, str(r.exchange).rstrip(".")) for r in answers],
            key=lambda x: x[0],
        )
        return records
    else:
        print("[!] dnspython not installed (pip install dnspython) -- "
              "cannot do a reliable automatic MX lookup.")
        print("    Use dnsdumpster.com / mxtoolbox.com to get the MX,")
        print("    then rerun with --mx-host <hostname> --mx-ip <ip>.")
        sys.exit(1)


def resolve_ip(hostname):
    return socket.gethostbyname(hostname)


# --------------------------------------------------------------------------
# DNS posture check (SPF/DMARC) - passive, read-only. Context for the
# active tests: the tested domain's own DMARC policy explains whether
# self-impersonation gets blocked, and the spoofed domain's own DMARC
# policy sets the bar for what a compliant receiving gateway should do
# with the spoofing test (p=reject should SMTP-reject; p=quarantine should
# accept then filter downstream; p=none sets no expectation either way).
# --------------------------------------------------------------------------

def get_spf_record(domain):
    if not HAVE_DNSPYTHON:
        return "(check unavailable: dnspython not installed)"
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for r in answers:
            txt = b"".join(r.strings).decode(errors="replace") if hasattr(r, "strings") else str(r).strip('"')
            if txt.startswith("v=spf1"):
                return txt
    except Exception:
        pass
    return None


def get_dmarc_record(domain):
    if not HAVE_DNSPYTHON:
        return "(check unavailable: dnspython not installed)"
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            txt = b"".join(r.strings).decode(errors="replace") if hasattr(r, "strings") else str(r).strip('"')
            if txt.startswith("v=DMARC1"):
                return txt
    except Exception:
        pass
    return None


def check_dns_posture(client_domain, spoof_from):
    spoof_domain = spoof_from.split("@")[-1]
    posture = {
        "client_domain": client_domain,
        "client_spf": get_spf_record(client_domain),
        "client_dmarc": get_dmarc_record(client_domain),
        "spoof_domain": spoof_domain,
        "spoof_spf": get_spf_record(spoof_domain),
        "spoof_dmarc": get_dmarc_record(spoof_domain),
    }
    print("--- DNS posture check (SPF/DMARC) ---")
    print(f"  {client_domain} SPF   : {posture['client_spf'] or '(none found)'}")
    print(f"  {client_domain} DMARC : {posture['client_dmarc'] or '(none found)'}")
    print(f"  {spoof_domain} SPF   : {posture['spoof_spf'] or '(none found)'}")
    print(f"  {spoof_domain} DMARC : {posture['spoof_dmarc'] or '(none found)'}\n")
    return posture


# --------------------------------------------------------------------------
# A test = one raw SMTP transaction, with its own result interpretation
# --------------------------------------------------------------------------

class SmtpTest:
    def __init__(self, key, title, mail_from, rcpt_to, subject, body,
                 good_outcome, raw_message_builder=None):
        self.key = key
        self.title = title
        self.mail_from = mail_from
        self.rcpt_to = rcpt_to
        self.subject = subject
        self.body = body
        self.good_outcome = good_outcome  # what we expect to see
        # Optional: callable(from_name, to_name) -> str (full RFC822
        # message, headers included). Used for tests that need a MIME
        # multipart body (e.g. inline QR code) instead of the plain text
        # built by message_source().
        self.raw_message_builder = raw_message_builder
        self.transcript = []
        self.final_code = None
        self.final_message = ""

    def message_source(self, from_name, to_name):
        if self.raw_message_builder:
            return self.raw_message_builder(from_name, to_name)
        return (
            f"From: {from_name} <{self.mail_from}>\r\n"
            f"To: {to_name} <{self.rcpt_to}>\r\n"
            f"Subject: {self.subject}\r\n"
            f"\r\n"
            f"{self.body}\r\n"
        )

    def run(self, ip, helo_domain, from_name, to_name, timeout=15, port=25):
        """Opens a raw SMTP connection (HELO / MAIL FROM / RCPT TO / DATA)
        and captures every response, just like a manual telnet session on
        port 25."""
        self.transcript = []
        try:
            with smtplib.SMTP(timeout=timeout) as smtp:
                smtp.set_debuglevel(0)
                code, msg = smtp.connect(ip, port)
                self._log("CONNECT", code, msg)

                code, msg = smtp.helo(helo_domain)
                self._log(f"HELO {helo_domain}", code, msg)
                if code >= 400:
                    self.final_code, self.final_message = code, msg.decode() if isinstance(msg, bytes) else msg
                    return self

                code, msg = smtp.mail(self.mail_from)
                self._log(f"MAIL FROM:<{self.mail_from}>", code, msg)
                if code >= 400:
                    self.final_code, self.final_message = code, msg.decode() if isinstance(msg, bytes) else msg
                    return self

                code, msg = smtp.rcpt(self.rcpt_to)
                self._log(f"RCPT TO:<{self.rcpt_to}>", code, msg)
                if code >= 400:
                    # E.g. 550 Relay Access Denied -- that's the expected
                    # (good) outcome for the relay test.
                    self.final_code, self.final_message = code, msg.decode() if isinstance(msg, bytes) else msg
                    return self

                data = self.message_source(from_name, to_name)
                code, msg = smtp.data(data)
                self._log("DATA + message body", code, msg)
                self.final_code, self.final_message = code, msg.decode() if isinstance(msg, bytes) else msg

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            self._log("NETWORK ERROR", -1, str(e))
            self.final_code, self.final_message = -1, str(e)

        return self

    def _log(self, step, code, msg):
        if isinstance(msg, bytes):
            msg = msg.decode(errors="replace")
        self.transcript.append((step, code, msg))

    def verdict(self):
        if self.final_code is None:
            return "NOT RUN"
        if self.final_code == -1:
            return f"NETWORK ERROR ({self.final_message})"
        if self.key == "relay":
            # For this test, a refusal IS the good outcome -- whether
            # permanent (5xx, e.g. 554 Relay access denied) or temporary
            # (4xx, e.g. 454 4.7.1 Relay access denied, produced by
            # defer_unauth_destination). Only a 2xx code means the
            # message was actually accepted for relay.
            if self.final_code >= 400:
                return f"OK - relay refused (code {self.final_code}, good sign)"
            return f"RISK - relay accepted (code {self.final_code})"
        else:
            if self.final_code in (250,) or (200 <= self.final_code < 300):
                return f"RISK - message accepted (code {self.final_code})"
            return f"OK - message rejected (code {self.final_code})"


# --------------------------------------------------------------------------
# Test 4 (optional): QR-code awareness test
#
# Deliberately generic template -- no third-party brand impersonation. The
# QR code is generated on the fly from a URL supplied by the operator
# (--qr-url), typically a tracking page controlled by Integrity, not a real
# brand link. The sender stays internal to the tested domain (no brand
# spoofing here, just an open/scan test).
# --------------------------------------------------------------------------

def generate_qr_png(data):
    if not HAVE_QRCODE:
        print("[!] The 'qrcode' module is not installed -- "
              "pip install \"qrcode[pil]\" to enable the QR test.")
        sys.exit(1)
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def build_qr_raw_message(qr_png_bytes, subject, mail_from, rcpt_to, note):
    def _builder(from_name, to_name):
        msg = MIMEMultipart("related")
        msg["From"] = f"{from_name} <{mail_from}>"
        msg["To"] = f"{to_name} <{rcpt_to}>"
        msg["Subject"] = subject

        html = (
            "<html><body>"
            "<p>Hello,</p>"
            f"<p>{note}</p>"
            "<p>Please scan the QR code below with your mobile device to "
            "continue.</p>"
            '<img src="cid:qrimage" alt="QR Code" width="220" height="220">'
            "<p>This is an awareness test performed by Integrity as part "
            "of an authorized mandate. Please let us know if you scanned "
            "this code (no personal data is collected).</p>"
            "</body></html>"
        )
        msg.attach(MIMEText(html, "html"))

        img_part = MIMEImage(qr_png_bytes, _subtype="png")
        img_part.add_header("Content-ID", "<qrimage>")
        img_part.add_header("Content-Disposition", "inline", filename="qrcode.png")
        msg.attach(img_part)

        return msg.as_string()

    return _builder


# --------------------------------------------------------------------------
# Build the 3 (or 4) tests from the client's parameters
# --------------------------------------------------------------------------

def build_tests(args):
    disclaimer = (
        "Hello,\r\n\r\n"
        "This is a test performed by Integrity. If you receive this "
        "email, please send us a screenshot (and let us know whether it "
        "landed in your inbox, junk, or spam folder).\r\n\r\n"
        "Thank you."
    )

    tests = [
        SmtpTest(
            key="unauth",
            title="Unauthenticated send test",
            mail_from=args.internal_email,
            rcpt_to=args.internal_email,
            subject="Integrity Unauthenticated Test",
            body=disclaimer,
            good_outcome="The MX should reject or filter this message.",
        ),
        SmtpTest(
            key="spoof",
            title="Spoofing test",
            mail_from=args.spoof_from,
            rcpt_to=args.internal_email,
            subject="Integrity Spoofing Test",
            body=disclaimer,
            good_outcome="SPF/DKIM/DMARC should block or flag this message.",
        ),
    ]

    if args.relay_test_email:
        tests.append(
            SmtpTest(
                key="relay",
                title="Open mail relay test",
                mail_from=args.internal_email,
                rcpt_to=args.relay_test_email,
                subject="Integrity Mail Relay Test",
                body=(
                    "Hello,\r\n\r\n"
                    "This is a test performed by Integrity. If you "
                    "receive this email, the MX that was tested can be "
                    "used as a mail relay.\r\n\r\nThank you."
                ),
                good_outcome="The MX should refuse (code 550, Relay Access Denied).",
            )
        )

    if args.qr_url:
        qr_png = generate_qr_png(args.qr_url)
        tests.append(
            SmtpTest(
                key="qr",
                title="QR-code awareness test",
                mail_from=args.qr_from,
                rcpt_to=args.internal_email,
                subject=args.qr_subject,
                body=None,
                good_outcome="The message/attachment should be filtered, "
                              "or the user should not scan the QR code.",
                raw_message_builder=build_qr_raw_message(
                    qr_png, args.qr_subject, args.qr_from, args.internal_email,
                    args.qr_note,
                ),
            )
        )

    return tests


# --------------------------------------------------------------------------
# Final report + heads-up email, ready to paste
# --------------------------------------------------------------------------

def render_heads_up_email(domain):
    return (
        "Subject: Hardening test MX Record - <Client> - "
        f"{datetime.date.today():%d/%m/%Y}\n\n"
        "Hello,\n\n"
        f"We will shortly be testing the MX servers of {domain} by "
        "sending a spoofing email, pretending to be someone from within "
        "the organization, and checking for a mail relay vulnerability. "
        "You may receive an email that appears to come from someone "
        "inside your organization, with a message signed by "
        "Integrity.\n\n"
        "We will send you screenshots once the tests are complete.\n\n"
        "Thank you."
    )


def render_report(domain, mx_host, mx_ip, posture, tests):
    lines = []
    lines.append(f"Subject: MX Server Test Summary - <Client> - "
                  f"{datetime.date.today():%d/%m/%Y}\n")
    lines.append("Hello,\n")
    lines.append("Further to your approval to perform impersonation "
                  "tests on the email servers, below is the summary of "
                  f"the tests performed:\n")
    lines.append(f"- Domain tested: {domain}")
    lines.append(f"- MX tested: {mx_host} ({mx_ip})\n")
    lines.append("--- DNS posture check (SPF/DMARC) ---")
    lines.append(f"{posture['client_domain']} SPF: {posture['client_spf'] or '(none found)'}")
    lines.append(f"{posture['client_domain']} DMARC: {posture['client_dmarc'] or '(none found)'}")
    lines.append(f"{posture['spoof_domain']} SPF: {posture['spoof_spf'] or '(none found)'}")
    lines.append(f"{posture['spoof_domain']} DMARC: {posture['spoof_dmarc'] or '(none found)'}\n")
    lines.append("Tests performed:")
    for i, t in enumerate(tests, 1):
        lines.append(f"{i}. {t.title}")
    lines.append("")
    for t in tests:
        lines.append(f"--- {t.title} ---")
        lines.append(f"Result: {t.verdict()}")
        lines.append(f"Expected: {t.good_outcome}")
        lines.append("")
    lines.append(
        "If you receive an email from these tests, please attach a "
        "screenshot showing which folder it landed in (inbox, junk, "
        "spam).\n"
    )
    lines.append("Thank you.")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Interactive mode: asks questions one by one instead of requiring the
# full command line. Triggered automatically when the script is run with
# no argument (`python bdika_mx.py`).
# --------------------------------------------------------------------------

def _ask(prompt, default=None, required=False):
    suffix = f" [{default}]" if default else ""
    while True:
        val = input(f"{prompt}{suffix}: ").strip()
        if not val and default is not None:
            return default
        if not val and required:
            print("    -> required, please enter a value.")
            continue
        return val or None


def run_wizard(parser):
    # Starting namespace = every parser default (qr-subject, qr-note,
    # from-name, to-name, out-dir, etc.) without requiring anything.
    args = parser.parse_args([])

    print("\n=== DICA MX interactive assistant ===")
    print("(Press Enter to accept the default in [ ], or to skip a test)\n")

    args.domain = _ask("Client domain to test (e.g. client-domain.com)", required=True)
    args.internal_email = _ask(
        f"Internal control address on {args.domain} (e.g. firstname@{args.domain})",
        required=True,
    )
    args.relay_test_email = _ask(
        "External mailbox for the relay test (Enter = skip this test)"
    )
    args.spoof_from = _ask(
        "External address to spoof", default=args.spoof_from
    )
    args.qr_url = _ask(
        "URL to encode in the QR code, awareness test (Enter = skip this test)"
    )

    mx_ip = _ask("Force the MX IP manually (Enter = automatic DNS lookup)")
    if mx_ip:
        args.mx_ip = mx_ip
        args.mx_host = _ask("Matching MX hostname (for HELO)", default=args.domain)

    print("\n--- Summary ---")
    print(f"  Domain          : {args.domain}")
    print(f"  Internal mailbox: {args.internal_email}")
    print(f"  Relay test      : {args.relay_test_email or '(skipped)'}")
    print(f"  Spoof From      : {args.spoof_from}")
    print(f"  QR test         : {args.qr_url or '(skipped)'}")
    if mx_ip:
        print(f"  MX forced       : {args.mx_host} ({args.mx_ip})")
    print()

    ans = input("Do you confirm you have a signed client mandate "
                 "authorizing this test? (type 'yes' to continue): ")
    if ans.strip().lower() not in ("yes", "y", "oui"):
        print("Cancelled.")
        sys.exit(1)
    args.confirm_authorized = True  # already confirmed above, no double prompt

    return args


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="DICA MX tool - authorized use only, as part of a "
                     "signed client mandate. Run with no argument for "
                     "interactive mode.")
    p.add_argument("domain", nargs="?", default=None,
                   help="Client domain to test, e.g. client-domain.com "
                        "(omit for interactive mode)")
    p.add_argument("--internal-email", default=None,
                   help="Internal client address used as the sender/recipient control")
    p.add_argument("--relay-test-email", default=None,
                   help="External mailbox (e.g. an Integrity control Gmail) for the relay test. Omit to skip this test.")
    p.add_argument("--spoof-from", default="support@amazon.com",
                   help="External address to spoof for the spoofing test (default: support@amazon.com, as in the historical template)")
    p.add_argument("--qr-url", default=None,
                   help="Enables the QR-code awareness test: URL (a tracking page controlled by Integrity, NOT a real brand link) encoded in the QR code. Omit to skip this test.")
    p.add_argument("--qr-from", default=None,
                   help="Sender address for the QR test (default: security@<domain>, generic, no third-party brand)")
    p.add_argument("--qr-subject", default="Security Alert - Action Required",
                   help="Subject of the QR test message (generic template)")
    p.add_argument("--qr-note", default=(
                       "Unusual activity was detected on your account."),
                   help="Generic hook sentence shown before the QR code")
    p.add_argument("--mx-host", default=None, help="Force the MX hostname (otherwise automatic DNS lookup)")
    p.add_argument("--mx-ip", default=None, help="Force the MX IP (otherwise resolved from --mx-host or the lookup)")
    p.add_argument("--smtp-port", type=int, default=25, help="SMTP port to connect to (default: 25)")
    p.add_argument("--helo-domain", default=None, help="HELO domain (default: --domain)")
    p.add_argument("--from-name", default="Integrity", help="Name shown in the From field of the messages")
    p.add_argument("--to-name", default="Client", help="Name shown in the To field of the messages")
    p.add_argument("--confirm-authorized", action="store_true",
                   help="Confirms this campaign is covered by a signed client mandate (otherwise an interactive confirmation is requested)")
    p.add_argument("--out-dir", default="./dica_mx_reports",
                   help="Output directory for the logs and report")
    args = p.parse_args()

    if args.domain is None:
        # No argument given -> interactive mode.
        args = run_wizard(p)
    elif not args.internal_email:
        p.error("--internal-email is required in command-line mode "
                 "(or run the script with no argument for interactive mode)")

    helo_domain = args.helo_domain or args.domain
    if args.qr_url and not args.qr_from:
        args.qr_from = f"security@{args.domain}"

    print(f"=== DICA MX - {args.domain} ===\n")

    if not args.confirm_authorized:
        print("This script sends real SMTP messages (including a "
              f"spoofed From) to the mail server of {args.domain}.")
        ans = input("Do you confirm you have a signed client mandate "
                     "authorizing this test? (type 'yes' to continue): ")
        if ans.strip().lower() not in ("yes", "y", "oui"):
            print("Cancelled.")
            sys.exit(1)

    # --- Reconnaissance -----------------------------------------------
    if args.mx_host and args.mx_ip:
        mx_host, mx_ip = args.mx_host, args.mx_ip
        print(f"[i] MX forced: {mx_host} ({mx_ip})")
    else:
        print(f"[i] Looking up MX for {args.domain} ...")
        records = lookup_mx(args.domain)
        if not records:
            print("[!] No MX record found.")
            sys.exit(1)
        for pref, host in records:
            print(f"    priority {pref:>3}  {host}")
        mx_host = args.mx_host or records[0][1]
        mx_ip = args.mx_ip or resolve_ip(mx_host)
        print(f"[i] MX selected: {mx_host} -> {mx_ip}\n")

    # --- DNS posture check (SPF/DMARC) ----------------------------------
    posture = check_dns_posture(args.domain, args.spoof_from)

    # --- Tests -----------------------------------------------------------
    tests = build_tests(args)
    for t in tests:
        print(f"--- {t.title} ---")
        t.run(mx_ip, helo_domain, args.from_name, args.to_name, port=args.smtp_port)
        for step, code, msg in t.transcript:
            print(f"    {step:<45} -> {code} {msg.splitlines()[0] if msg else ''}")
        print(f"    => {t.verdict()}\n")

    # --- Output ------------------------------------------------------------
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    domain_slug = args.domain.replace(".", "_")

    log_path = out_dir / f"{domain_slug}_{stamp}_log.json"
    report_path = out_dir / f"{domain_slug}_{stamp}_report.txt"
    heads_up_path = out_dir / f"{domain_slug}_{stamp}_heads_up_email.txt"

    log_data = {
        "domain": args.domain,
        "mx_host": mx_host,
        "mx_ip": mx_ip,
        "timestamp": stamp,
        "dns_posture": posture,
        "tests": [
            {
                "key": t.key,
                "title": t.title,
                "mail_from": t.mail_from,
                "rcpt_to": t.rcpt_to,
                "transcript": t.transcript,
                "final_code": t.final_code,
                "verdict": t.verdict(),
            }
            for t in tests
        ],
    }
    log_path.write_text(json.dumps(log_data, indent=2, ensure_ascii=False), encoding="utf-8")
    report_path.write_text(render_report(args.domain, mx_host, mx_ip, posture, tests), encoding="utf-8")
    heads_up_path.write_text(render_heads_up_email(args.domain), encoding="utf-8")

    print(f"[OK] JSON log       : {log_path}")
    print(f"[OK] Report         : {report_path}")
    print(f"[OK] Heads-up email (send BEFORE starting the tests, for reference): {heads_up_path}")


if __name__ == "__main__":
    main()
