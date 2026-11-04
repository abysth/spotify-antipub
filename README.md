# Spotify Anti-Pub 🎵🚫

Bloqueur de publicités Spotify **100 % local et open source**, écrit en Python,
sans modifier un seul fichier de Spotify.

## Comment ça marche ?

Les pubs Spotify (audio et bannières) sont demandées par le client via des
**chemins d'URL** sur `spclient.spotify.com` :

```
/ads/v3/ads?slots=preroll     ← la pub audio avant la chanson
/ad-logic/prefetch             ← la logique publicitaire
/ad-logic/v3/config
/gabo-receiver-service/...     ← le tracking
/audio-ads/...
```

Un simple blocage DNS/fichier `hosts` ne peut **pas** toucher à ces chemins
(sans casser Spotify, car le domaine sert aussi la musique). D'où l'approche :

1. **Certificat local** : l'outil génère une autorité de certification (CA)
   locale et l'installe dans *Certificat : Utilisateur courant → Racines*
   (aucun administrateur requis, révocable en un clic).
2. **Proxy local** : un proxy HTTPS tourne sur `127.0.0.1:9797`. Spotify est
   lancé avec `--proxy-server=http://127.0.0.1:9797` — uniquement Spotify
   (raccourci + protocole `spotify:`) passe par lui.
3. **Filtrage** : le proxy inspecte les requêtes des hôtes `*spclient*`,
   **bloque les chemins publicitaires** et **relaie tout le reste** intact
   (métadonnées, playlists, DRM, lecture…). Les autres domaines (musique,
   CDN) transitent en tunnel brut, non inspectés.

Résultat : les pubs reçoivent un `404` → le client n'a aucune pub à jouer.

> La liste de chemins est celle du projet Linux
> [spotify-adblock](https://github.com/abba23/spotify-adblock) (hook
> `cef_urlrequest_create`), transposée ici en proxy pour Windows.

## Utilisation

### La commande unique

```powershell
python antipub.py
```

**C'est tout.** Cette commande installe ce qui manque (certificat, réglages)
puis démarre le proxy. Elle est déjà faite : si tout est en place, elle vous le
dit et ne refait rien.

| Commande | À quoi elle sert (rarement besoin) |
|---|---|
| `python antipub.py` | **Lancer** (installe + démarre) |
| `python antipub.py status` | Vérifier que tout marche |
| `python antipub.py stop` | Couper la protection |
| `python antipub.py uninstall` | Tout supprimer, Spotify redevient normal |

### Au quotidien

Une fois installé **rien à faire** : le proxy démarre tout seul à chaque
connexion Windows, et tous les raccourcis Spotify (Menu Démarrer, Bureau,
Barre des tâches) passent par lui. Ouvrez Spotify, c'est protégé.

En cas de souci, double-cliquez sur `demarrer.bat` (= `python antipub.py`).

## Sécurité — à savoir

- La CA locale est installée **uniquement** dans le magasin *Utilisateur
  courant* (pas la machine). Elle sert uniquement à terminer les connexions
  TLS vers les hôtes Spotify dans le proxy local.
- Le proxy **ne relaie que du clair** sauf pour les hôtes `*spclient*`
  (où il doit lire les chemins). Aucune donnée n'est envoyée ailleurs : tout
  est local.
- `desinstaller.bat` supprime la CA, restaure le raccourci et le protocole.
- La CA locale étant une racine de confiance, **ne la laissez pas traîner si
  vous n'utilisez plus l'outil** : désinstallez proprement.

## Limites

- Ne concerne que le **client Spotify Windows** (pas le site web, pas le
  téléphone).
- Les sections sponsorisées purement *éditoriales* (playlists « sponsorisées »
  suggérées) sont du contenu légitime côté serveur et peuvent rester visibles.
- Spotify peut recréer son raccourci lors d'une mise à jour → relancez
  `demarrer.bat` (qui re-applique les réglages) si les pubs reviennent.
- Si Spotify ne se connecte plus : le proxy ne tourne pas → `demarrer.bat`.

## Dépannage

| Symptôme | Solution |
|---|---|
| Spotify affiche « hors ligne » | Lancez `python antipub.py` (le proxy était éteint) |
| Les pubs sont revenues | Lancez `python antipub.py status` puis `python antipub.py` |
| Rien ne se passe | Regardez `antipub.log` |
| Tout retirer | `desinstaller.bat` |

## Fichiers

- `antipub.py` — l'outil (Python 3.10+, `cryptography` pour les certificats)
- `certs/` — CA locale + certificat `*.spotify.com` (générés à l'install)
- `state.json` — valeurs d'origine sauvegardées (restauration exacte)
- `antipub.log` — journal de toutes les requêtes (OK / BLOQUE)

## Crédits

- Liste de filtrage : [abba23/spotify-adblock](https://github.com/abba23/spotify-adblock) (MIT)
- Solution de repli éprouvée si besoin : [SpotX](https://github.com/SpotX-Official/SpotX) (patch binaire du client)
