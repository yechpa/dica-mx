# Serveur Postfix de test — labo DICA MX

Serveur mail jetable pour valider `bdika_mx.py` avant de le pointer sur un
vrai client. Pas de vraie zone DNS requise : `bdika_mx.py` accepte `--mx-ip`
en direct.

## Déploiement sur le serveur (une fois l'IP + la clé SSH en place)

```bash
scp -r postfix-test-server/ user@<IP_SERVEUR>:~/dica-mx-lab
ssh user@<IP_SERVEUR>
cd ~/dica-mx-lab
cp .env.example .env
docker compose up -d --build
docker compose logs -f
```

Le port **25** du serveur doit être ouvert dans le firewall/security group
pour que `bdika_mx.py`, lancé depuis ta machine, puisse s'y connecter.

## Comportement par défaut

- Domaine de test : `labdomain.test` (modifiable via `.env`)
- Boîte interne de contrôle : `test@labdomain.test`
- Relais : **fermé** (comportement standard Postfix "Internet Site") →
  toute tentative de relais vers un destinataire externe doit être refusée
  (code `554`/`550 Relay access denied`).

## Lancer `bdika_mx.py` contre ce labo

Pas besoin de lookup DNS MX réel — on force l'IP directement :

```bash
python bdika_mx.py labdomain.test \
    --mx-host mail.labdomain.test \
    --mx-ip <IP_SERVEUR> \
    --internal-email test@labdomain.test \
    --relay-test-email controle.externe@example.com \
    --confirm-authorized
```

Résultat attendu :
- `unauth` et `spoof` → `RISQUE — message accepte (code 250)` (normal : rien
  ne filtre encore côté labo, c'est un Postfix nu)
- `relay` → `OK — relais refuse (code 554 ou 550)`

## Tester le cas "relais ouvert" (vérifier que le script détecte bien le RISQUE)

```bash
# sur le serveur
echo "OPEN_RELAY=true" >> .env
docker compose up -d --build
```

Relancer `bdika_mx.py` : le test `relay` doit maintenant remonter
`RISQUE — relais accepte (code 250)`.

Remettre `OPEN_RELAY=false` ensuite et redéployer pour revenir à l'état
sûr par défaut.

## Lire le courrier reçu directement sur le serveur

```bash
docker exec -it dica-mx-lab mail -u test
```

ou suivre les transactions SMTP en direct :

```bash
docker compose logs -f
```

## Nettoyage

```bash
docker compose down -v   # -v supprime aussi les volumes (boîtes, logs)
```

---
**Rappel** : ce labo est volontairement non sécurisé (relais activable,
pas de TLS, pas de SPF/DKIM/DMARC) — à garder isolé (VM jetable, pas
d'IP publique exposée plus longtemps que nécessaire) et jamais relié à un
vrai domaine de production.
