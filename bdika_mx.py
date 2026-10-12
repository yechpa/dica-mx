#!/usr/bin/env python3
"""
dica_mx.py - Outil DICA MX (Diagnostic d'Infrastructure de Courrier Applicatif)

Automatise le flux decrit dans "How to start MX Record Check.pdf" :
  1) Reconnaissance DNS (lookup MX reel du domaine client)
  2) Test non authentifie
  3) Test d'usurpation (spoofing)
  4) Test de relais ouvert (mail relay)
  5) Test de sensibilisation QR code (optionnel, --qr-url ; gabarit generique,
     aucune marque tierce usurpee)
  6) Interpretation des codes SMTP (250 = accepte, 550/55x = relais refuse = bon signe)
  7) Generation d'un rapport pret a coller dans l'email de fin de mission

USAGE RESERVE : tests d'intrusion autorises, dans le cadre d'un mandat client
signe. Ce script envoie de vrais messages SMTP bruts (y compris un "From"
usurpe) au serveur mail du domaine cible -- ne jamais l'utiliser hors mandat.

Exemple :
    python dica_mx.py client-domaine.com \\
        --internal-email prenom.nom@client-domaine.com \\
        --relay-test-email controle.integrity@gmail.com \\
        --spoof-from support@fournisseur-externe.example \\
        --confirm-authorized

Sans --confirm-authorized, le script demande une confirmation interactive
avant d'envoyer quoi que ce soit.
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

# Console Windows (cp1252) par defaut -> incapable d'afficher certains
# caracteres (accents, puces). On force stdout/stderr en UTF-8 quand possible,
# et on retombe sur un remplacement silencieux sinon (jamais de crash pour
# un simple print).
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
# Reconnaissance : trouver les MX du domaine cible
# --------------------------------------------------------------------------

def lookup_mx(domain):
    """Retourne une liste de (priorite, hostname) triee, via dnspython si
    disponible, sinon via socket.getaddrinfo en dernier recours (moins fiable
    pour du MX pur, donc dnspython est fortement recommande)."""
    if HAVE_DNSPYTHON:
        answers = dns.resolver.resolve(domain, "MX")
        records = sorted(
            [(r.preference, str(r.exchange).rstrip(".")) for r in answers],
            key=lambda x: x[0],
        )
        return records
    else:
        print("[!] dnspython non installe (pip install dnspython) -- "
              "impossible de faire un lookup MX fiable automatiquement.")
        print("    Utilise dnsdumpster.com / mxtoolbox.com pour recuperer le MX,")
        print("    puis relance avec --mx-host <hostname> --mx-ip <ip>.")
        sys.exit(1)


def resolve_ip(hostname):
    return socket.gethostbyname(hostname)


# --------------------------------------------------------------------------
# Un test = une transaction SMTP brute, avec sa propre lecture de resultat
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
        self.good_outcome = good_outcome  # texte : ce qu'on espere voir
        # Optionnel : callable(from_name, to_name) -> str (message RFC822
        # complet, headers inclus). Utilise pour les tests qui ont besoin
        # d'un corps MIME multipart (ex. QR code inline) plutot que du
        # texte brut genere par message_source().
        self.raw_message_builder = raw_message_builder
        self.transcript = []
        self.final_code = None
        self.final_message = ""

    def message_source(self, from_name, to_name):
        if self.raw_message_builder:
            return self.raw_message_builder(from_name, to_name)
        return (
            f"FROM: {from_name} <{self.mail_from}>\r\n"
            f"TO: {to_name} <{self.rcpt_to}>\r\n"
            f"Subject: {self.subject}\r\n"
            f"\r\n"
            f"{self.body}\r\n"
        )

    def run(self, ip, helo_domain, from_name, to_name, timeout=15):
        """Ouvre une connexion SMTP brute (HELO / MAIL FROM / RCPT TO / DATA)
        et capture chaque reponse, comme un telnet manuel sur le port 25."""
        self.transcript = []
        try:
            with smtplib.SMTP(timeout=timeout) as smtp:
                smtp.set_debuglevel(0)
                code, msg = smtp.connect(ip, 25)
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
                    # Ex. 550 Relay Access Denied -- c'est le resultat attendu
                    # (bon signe) pour le test de relais.
                    self.final_code, self.final_message = code, msg.decode() if isinstance(msg, bytes) else msg
                    return self

                data = self.message_source(from_name, to_name)
                code, msg = smtp.data(data)
                self._log("DATA + corps du message", code, msg)
                self.final_code, self.final_message = code, msg.decode() if isinstance(msg, bytes) else msg

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            self._log("ERREUR RESEAU", -1, str(e))
            self.final_code, self.final_message = -1, str(e)

        return self

    def _log(self, step, code, msg):
        if isinstance(msg, bytes):
            msg = msg.decode(errors="replace")
        self.transcript.append((step, code, msg))

    def verdict(self):
        if self.final_code is None:
            return "NON EXECUTE"
        if self.final_code == -1:
            return f"ERREUR RESEAU ({self.final_message})"
        if self.key == "relay":
            # Pour ce test, un refus EST le bon resultat -- qu'il soit
            # permanent (5xx, ex. 554 Relay access denied) ou temporaire
            # (4xx, ex. 454 4.7.1 Relay access denied, produit par
            # defer_unauth_destination). Seul un code 2xx signifie que le
            # message a reellement ete accepte pour relais.
            if self.final_code >= 400:
                return f"OK — relais refuse (code {self.final_code}, bon signe)"
            return f"RISQUE — relais accepte (code {self.final_code})"
        else:
            if self.final_code in (250,) or (200 <= self.final_code < 300):
                return f"RISQUE — message accepte (code {self.final_code})"
            return f"OK — message refuse (code {self.final_code})"


# --------------------------------------------------------------------------
# Test 4 (optionnel) : sensibilisation par QR code
#
# Gabarit volontairement generique -- aucune marque tierce usurpee. Le QR
# code est genere a la volee a partir d'une URL fournie par l'operateur
# (--qr-url), typiquement une page de suivi controlee par Integrity, pas un
# lien reel. L'expediteur reste interne au domaine teste (pas de spoofing de
# marque ici, uniquement un test d'ouverture/scan).
# --------------------------------------------------------------------------

def generate_qr_png(data):
    if not HAVE_QRCODE:
        print("[!] Le module 'qrcode' n'est pas installe -- "
              "pip install \"qrcode[pil]\" pour activer le test QR.")
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
            "<p>Bonjour,</p>"
            f"<p>{note}</p>"
            "<p>Merci de scanner le QR code ci-dessous avec votre appareil "
            "mobile pour continuer.</p>"
            '<img src="cid:qrimage" alt="QR Code" width="220" height="220">'
            "<p>Ceci est un test de sensibilisation realise par Integrity "
            "dans le cadre d'un mandat autorise. Merci de nous indiquer si "
            "vous avez scanne ce code (aucune donnee personnelle n'est "
            "collectee).</p>"
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
# Construction des 3 (ou 4) tests a partir des parametres du client
# --------------------------------------------------------------------------

def build_tests(args):
    disclaimer = (
        "Bonjour,\r\n\r\n"
        "Ceci est un test realise par Integrity. Si vous recevez cet email, "
        "merci de nous renvoyer une capture d'ecran (et de preciser s'il est "
        "arrive en boite de reception, indesirables ou spam).\r\n\r\n"
        "Merci."
    )

    tests = [
        SmtpTest(
            key="unauth",
            title="Test non authentifie",
            mail_from=args.internal_email,
            rcpt_to=args.internal_email,
            subject="Integrity Unauthenticated Test",
            body=disclaimer,
            good_outcome="Le MX devrait rejeter ou filtrer ce message.",
        ),
        SmtpTest(
            key="spoof",
            title="Test d'usurpation (spoofing)",
            mail_from=args.spoof_from,
            rcpt_to=args.internal_email,
            subject="Integrity Spoofing Test",
            body=disclaimer,
            good_outcome="SPF/DKIM/DMARC devraient bloquer ou marquer ce message.",
        ),
    ]

    if args.relay_test_email:
        tests.append(
            SmtpTest(
                key="relay",
                title="Test de relais ouvert (mail relay)",
                mail_from=args.internal_email,
                rcpt_to=args.relay_test_email,
                subject="Integrity Mail Relay Test",
                body=(
                    "Bonjour,\r\n\r\n"
                    "Ceci est un test realise par Integrity. Si vous recevez "
                    "cet email, le MX teste peut etre utilise comme relais "
                    "de courrier.\r\n\r\nMerci."
                ),
                good_outcome="Le MX devrait refuser (code 550, Relay Access Denied).",
            )
        )

    if args.qr_url:
        qr_png = generate_qr_png(args.qr_url)
        tests.append(
            SmtpTest(
                key="qr",
                title="Test de sensibilisation (QR code)",
                mail_from=args.qr_from,
                rcpt_to=args.internal_email,
                subject=args.qr_subject,
                body=None,
                good_outcome="Le message/la piece jointe devrait etre filtre "
                              "ou l'utilisateur ne devrait pas scanner le QR.",
                raw_message_builder=build_qr_raw_message(
                    qr_png, args.qr_subject, args.qr_from, args.internal_email,
                    args.qr_note,
                ),
            )
        )

    return tests


# --------------------------------------------------------------------------
# Rapport final + email de prevenance, prets a coller
# --------------------------------------------------------------------------

def render_heads_up_email(domain):
    return (
        "Objet : Hardening test MX Record - <Client> - "
        f"{datetime.date.today():%d/%m/%Y}\n\n"
        "Bonjour,\n\n"
        f"Nous allons prochainement tester les serveurs MX de {domain} en "
        "envoyant un email d'usurpation (se faisant passer pour quelqu'un de "
        "l'organisation) et en verifiant la possibilite de relais mail. "
        "Il est possible que vous receviez un email provenant apparemment "
        "d'une adresse interne, avec un message signe Integrity.\n\n"
        "Nous vous enverrons les captures d'ecran une fois les tests "
        "termines.\n\nMerci."
    )


def render_report(domain, mx_host, mx_ip, tests):
    lines = []
    lines.append(f"Objet : MX Server Test Summary - <Client> - "
                  f"{datetime.date.today():%d/%m/%Y}\n")
    lines.append("Bonjour,\n")
    lines.append("Suite a votre autorisation de realiser des tests "
                  "d'usurpation sur les serveurs mail, voici le resume des "
                  f"tests effectues :\n")
    lines.append(f"- Domaine teste : {domain}")
    lines.append(f"- Enregistrement MX teste : {mx_host} ({mx_ip})\n")
    lines.append("Tests realises :")
    for i, t in enumerate(tests, 1):
        lines.append(f"{i}. {t.title}")
    lines.append("")
    for t in tests:
        lines.append(f"--- {t.title} ---")
        lines.append(f"Resultat : {t.verdict()}")
        lines.append(f"Attendu  : {t.good_outcome}")
        lines.append("")
    lines.append(
        "Si vous recevez un email issu de ces tests, merci de joindre une "
        "capture d'ecran indiquant la boite dans laquelle il est arrive "
        "(reception, indesirables, spam).\n"
    )
    lines.append("Merci.")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Mode interactif : pose les questions une par une au lieu d'exiger la
# ligne de commande complete. Declenche automatiquement quand le script est
# lance sans argument (`python bdika_mx.py`).
# --------------------------------------------------------------------------

def _ask(prompt, default=None, required=False):
    suffix = f" [{default}]" if default else ""
    while True:
        val = input(f"{prompt}{suffix} : ").strip()
        if not val and default is not None:
            return default
        if not val and required:
            print("    -> requis, merci de saisir une valeur.")
            continue
        return val or None


def run_wizard(parser):
    # Namespace de depart = tous les defauts du parser (qr-subject,
    # qr-note, from-name, to-name, out-dir, etc.) sans rien exiger.
    args = parser.parse_args([])

    print("\n=== Assistant interactif — DICA MX ===")
    print("(Entree sans rien taper = valeur par defaut entre [ ], ou saute le test)\n")

    args.domain = _ask("Domaine du client a tester (ex: client-domaine.com)", required=True)
    args.internal_email = _ask(
        f"Adresse interne de controle sur {args.domain} (ex: prenom@{args.domain})",
        required=True,
    )
    args.relay_test_email = _ask(
        "Boite externe pour le test de relais (Entree = sauter ce test)"
    )
    args.spoof_from = _ask(
        "Adresse externe usurpee pour le test de spoofing", default=args.spoof_from
    )
    args.qr_url = _ask(
        "URL a encoder dans le QR, test de sensibilisation (Entree = sauter ce test)"
    )

    mx_ip = _ask("Forcer l'IP du MX manuellement (Entree = lookup DNS automatique)")
    if mx_ip:
        args.mx_ip = mx_ip
        args.mx_host = _ask("Hostname MX correspondant (pour le HELO)", default=args.domain)

    print("\n--- Recapitulatif ---")
    print(f"  Domaine        : {args.domain}")
    print(f"  Boite interne  : {args.internal_email}")
    print(f"  Test relais    : {args.relay_test_email or '(saute)'}")
    print(f"  Spoof From     : {args.spoof_from}")
    print(f"  Test QR        : {args.qr_url or '(saute)'}")
    if mx_ip:
        print(f"  MX force       : {args.mx_host} ({args.mx_ip})")
    print()

    ans = input("Confirmes-tu disposer d'un mandat client signe autorisant ce "
                 "test ? (taper 'oui' pour continuer) : ")
    if ans.strip().lower() not in ("oui", "yes", "y"):
        print("Annule.")
        sys.exit(1)
    args.confirm_authorized = True  # deja confirme ci-dessus, pas de double question

    return args


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="Outil DICA MX - usage reserve a des tests autorises "
                     "dans le cadre d'un mandat client signe. "
                     "Lance sans argument pour le mode interactif.")
    p.add_argument("domain", nargs="?", default=None,
                   help="Domaine du client a tester, ex: client-domaine.com "
                        "(omettre pour le mode interactif)")
    p.add_argument("--internal-email", default=None,
                   help="Adresse interne du client utilisee comme expediteur/destinataire de controle")
    p.add_argument("--relay-test-email", default=None,
                   help="Boite externe (ex: Gmail de controle Integrity) pour le test de relais. Omettre pour sauter ce test.")
    p.add_argument("--spoof-from", default="support@amazon.com",
                   help="Adresse externe usurpee pour le test de spoofing (defaut: support@amazon.com, comme dans le gabarit historique)")
    p.add_argument("--qr-url", default=None,
                   help="Active le test de sensibilisation QR : URL (page de suivi controlee par Integrity, PAS un vrai lien de marque) encodee dans le QR code. Omettre pour sauter ce test.")
    p.add_argument("--qr-from", default=None,
                   help="Adresse expediteur du test QR (defaut: securite@<domaine>, generique, aucune marque tierce)")
    p.add_argument("--qr-subject", default="Alerte de securite - Action requise",
                   help="Objet du message du test QR (gabarit generique)")
    p.add_argument("--qr-note", default=(
                       "Une activite inhabituelle a ete detectee sur votre "
                       "compte."),
                   help="Phrase d'accroche generique affichee avant le QR code")
    p.add_argument("--mx-host", default=None, help="Forcer le hostname MX (sinon lookup DNS automatique)")
    p.add_argument("--mx-ip", default=None, help="Forcer l'IP du MX (sinon resolue depuis --mx-host ou le lookup)")
    p.add_argument("--helo-domain", default=None, help="Domaine HELO (defaut: --domain)")
    p.add_argument("--from-name", default="Integrity", help="Nom affiche dans le FROM des messages")
    p.add_argument("--to-name", default="Client", help="Nom affiche dans le TO des messages")
    p.add_argument("--confirm-authorized", action="store_true",
                   help="Confirme que cette campagne est couverte par un mandat client signe (sinon confirmation interactive demandee)")
    p.add_argument("--out-dir", default="./dica_mx_reports",
                   help="Dossier de sortie pour les logs et le rapport")
    args = p.parse_args()

    if args.domain is None:
        # Aucun argument fourni -> mode interactif.
        args = run_wizard(p)
    elif not args.internal_email:
        p.error("--internal-email est requis en mode ligne de commande "
                 "(ou lance le script sans argument pour le mode interactif)")

    helo_domain = args.helo_domain or args.domain
    if args.qr_url and not args.qr_from:
        args.qr_from = f"securite@{args.domain}"

    print(f"=== DICA MX — {args.domain} ===\n")

    if not args.confirm_authorized:
        print("Ce script envoie de vrais messages SMTP (dont un From usurpe) "
              f"au serveur mail de {args.domain}.")
        ans = input("Confirmez-vous disposer d'un mandat client signe "
                     "autorisant ce test ? (taper 'oui' pour continuer) : ")
        if ans.strip().lower() not in ("oui", "yes", "y"):
            print("Annule.")
            sys.exit(1)

    # --- Reconnaissance -----------------------------------------------
    if args.mx_host and args.mx_ip:
        mx_host, mx_ip = args.mx_host, args.mx_ip
        print(f"[i] MX force : {mx_host} ({mx_ip})")
    else:
        print(f"[i] Lookup MX pour {args.domain} ...")
        records = lookup_mx(args.domain)
        if not records:
            print("[!] Aucun enregistrement MX trouve.")
            sys.exit(1)
        for pref, host in records:
            print(f"    priorite {pref:>3}  {host}")
        mx_host = args.mx_host or records[0][1]
        mx_ip = args.mx_ip or resolve_ip(mx_host)
        print(f"[i] MX retenu : {mx_host} -> {mx_ip}\n")

    # --- Tests -----------------------------------------------------------
    tests = build_tests(args)
    for t in tests:
        print(f"--- {t.title} ---")
        t.run(mx_ip, helo_domain, args.from_name, args.to_name)
        for step, code, msg in t.transcript:
            print(f"    {step:<45} -> {code} {msg.splitlines()[0] if msg else ''}")
        print(f"    => {t.verdict()}\n")

    # --- Sortie ------------------------------------------------------------
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    domain_slug = args.domain.replace(".", "_")

    log_path = out_dir / f"{domain_slug}_{stamp}_log.json"
    report_path = out_dir / f"{domain_slug}_{stamp}_rapport.txt"
    heads_up_path = out_dir / f"{domain_slug}_{stamp}_mail_prevenance.txt"

    log_data = {
        "domain": args.domain,
        "mx_host": mx_host,
        "mx_ip": mx_ip,
        "timestamp": stamp,
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
    report_path.write_text(render_report(args.domain, mx_host, mx_ip, tests), encoding="utf-8")
    heads_up_path.write_text(render_heads_up_email(args.domain), encoding="utf-8")

    print(f"[✓] Log JSON      : {log_path}")
    print(f"[✓] Rapport client: {report_path}")
    print(f"[✓] Mail prevenance (a envoyer AVANT les tests, pour reference): {heads_up_path}")


if __name__ == "__main__":
    main()
