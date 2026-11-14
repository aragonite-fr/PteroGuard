# PteroGuard

Détection d'activité illégale ou abusive sur les serveurs d'un hébergeur **Pterodactyl** (Wings + Docker).
Un seul script Python (bibliothèque standard, Python 3.11+), lancé comme service systemd sur le nœud Wings.

Par défaut il ne fait que lire : pas d'accès au socket Docker, ni à la base ou aux identifiants du panel.
La seule action qu'il fait, c'est le gel d'un conteneur, et seulement si l'option est activée. Ce gel est réversible.

## Ce qui est détecté

- **Processus** :
  - mineurs de cryptomonnaie, y compris les mineurs renommés repérés par leur usage CPU ;
  - processus camouflés en thread noyau ;
  - outils d'attaque, reverse shells, tunnels et proxys ;
  - exécutables lancés depuis /tmp ;
  - clients BitTorrent.
- **Réseau** (conntrack) :
  - pools de minage et relais Tor (listes mises à jour automatiquement) ;
  - SMTP sortant, scans de ports, bruteforce SSH/RDP/bases de données ;
  - ports BitTorrent ;
  - flood sortant ;
  - volume sortant horaire anormal.
- **Fichiers des volumes** :
  - signatures (malwares, IOC de .jar type fractureiser, phishing, carding, contenu pédocriminel par mots-clés et noms de fichiers, listes d'identifiants volés) ;
  - archives inspectées en mémoire ;
  - ClamAV, facultatif, via un conteneur clamd.
- **Web** : sondage HTTP des ports en écoute des conteneurs. Les listings de répertoires et les applis d'hébergement de fichiers sont signalés.
- **Logs** : Wings (SFTP) et nginx du panel.

## Niveaux et réactions

- **critique** et **alerte** : envoi immédiat. **info** : récap quotidien.
- Les alertes sont écrites dans `/var/log/ptero-guard/alertes.jsonl`. Elles sont aussi mises en file dans `/var/log/ptero-guard/discord.jsonl`, avec un message Discord prêt à envoyer par ligne, pour qu'un bot les relaie. Autre option : un webhook Discord dans `/etc/ptero-guard/webhook`.
- `auto_freeze = true` gèle le conteneur (`cgroup.freeze`) seulement sur les détections quasi certaines. `freeze_on_critique = true` le gèle sur toute alerte critique.

## Installation

```
sudo ./install.sh
sudoedit /etc/ptero-guard/config.toml     # panel_url, clamd_container, seuils, exceptions
ptero-guard status | alerts -n 20 | scan [--full] | test-alert | digest
ptero-guard freeze <uuid> | unfreeze <uuid>
```

La configuration par défaut se trouve dans `DEFAULTS` en tête de `ptero_guard.py`. Le fichier `config.toml` ne contient que les surcharges.

## Pare-feu sortant (facultatif)

`egress-firewall.sh` crée une table nftables dédiée, `inet ptero_egress`. Elle ne touche ni aux règles Docker ni à ufw. Elle :
- bloque le trafic des conteneurs vers Tor et vers les pools de minage, à partir des listes de PteroGuard ;
- plafonne le débit sortant de chaque conteneur (100 Mbit/s par défaut, variable `PTERO_EGRESS_RATE_KBYTES`).

```
sudo install -m 755 egress-firewall.sh /opt/ptero-guard/
sudo cp ptero-egress.service ptero-egress-refresh.service ptero-egress-refresh.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now ptero-egress ptero-egress-refresh.timer
sudo /opt/ptero-guard/egress-firewall.sh status      # retrait : systemctl disable --now ptero-egress
```

Le réseau visé est celui de Wings par défaut : `pterodactyl0`, `172.18.0.0/16`, `fdba:17c8:6c94::/64`.

## Limites

- Les images et vidéos ne sont pas analysées, seulement les noms de fichiers et les textes.
- Les sites passés par Cloudflare peuvent être couverts en plus par le *CSAM Scanning Tool* de Cloudflare.
- Les mots-clés peuvent déclencher des faux positifs. Les exceptions vont dans `[allow]`, par serveur ou par règle.

## Licence

PteroGuard est distribué sous la licence [PolyForm Noncommercial 1.0.0](LICENSE.md).

- **Usage non commercial** : libre et gratuit. Cela couvre l'usage personnel, l'apprentissage, la recherche, ainsi que les associations, les écoles et les organismes publics.
- **Usage commercial** : nécessite une licence payante. C'est le cas, par exemple, si vous protégez avec PteroGuard un service d'hébergement payant, ou si vous l'intégrez à une offre commerciale. Pour l'obtenir, écrivez à [contact@aragonite.fr](mailto:contact@aragonite.fr).
