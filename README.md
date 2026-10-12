# DICA MX

Outillage pour le Diagnostic d'Infrastructure de Courrier Applicatif (DICA)
de MX chez les clients Integrity : vérifier qu'un enregistrement MX ne
laisse pas passer un envoi non authentifié, une usurpation (spoofing), un
relais ouvert, ou un contenu de sensibilisation (QR code), lorsqu'on
l'interroge en SMTP brut sur le port 25.

**Usage réservé à des tests autorisés, dans le cadre d'un mandat client
signé.** Voir [bdika_mx.py](bdika_mx.py) pour le garde-fou de confirmation
intégré.

## Contenu

- **[bdika_mx.py](bdika_mx.py)** — script principal. Mode interactif
  (`python bdika_mx.py`) ou ligne de commande complète pour l'automatisation.
  Fait la reconnaissance DNS du MX, exécute les 4 tests, interprète les
  codes SMTP, et génère un rapport + un mail de prévenance prêts à coller.
- **[postfix-test-server/](postfix-test-server/)** — labo Docker (Postfix)
  pour valider le script sans toucher à un vrai domaine client. Toggle
  `OPEN_RELAY` pour tester les deux branches de détection.
- **How to start MX Record Check.pdf** — procédure manuelle d'origine
  (accès VPN client, reconnaissance, envoi des tests, rapport final) dont
  `bdika_mx.py` automatise le déroulé.
- **MX Record Sending Format(2).docx** — gabarits SMTP d'origine (texte
  brut des 4 tests).

## Démarrage rapide

```bash
pip install dnspython "qrcode[pil]"
python bdika_mx.py          # mode interactif, pose les questions une par une
```

Ou en ligne de commande :

```bash
python bdika_mx.py client-domaine.com \
    --internal-email prenom.nom@client-domaine.com \
    --relay-test-email controle.integrity@gmail.com \
    --qr-url "https://suivi.integrity.example/t/<id-unique>" \
    --confirm-authorized
```

## Important — réputation de l'IP de sortie

Les tests doivent partir d'une IP de sortie stable et déjà établie
(celle du VPN/bureau Integrity), pas d'une IP cloud ou résidentielle
ad hoc : les filtres anti-spam des MX clients (SORBS, Nemesis/IONOS, etc.)
bloquent souvent en amont une IP sans historique, ce qui fausse le
résultat du test (refus pour cause de réputation, pas de politique MX).
