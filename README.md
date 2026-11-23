# Gardien — antivirus Android

Détecte les logiciels espions et malveillants, puis guide leur suppression.

## Ce qu'il détecte
- **Logiciels espions connus** : nom d'appli, signature de l'éditeur, empreinte du fichier (base Échap, ~150 familles, ~3 200 échantillons).
- **Comportements suspects** : administrateur de l'appareil, accessibilité activée, lecture des notifications, appli cachée, installée hors magasin, faux nom « système », accès SMS/micro/position.
- **Failles du téléphone** : root, pas de verrouillage, correctifs de sécurité anciens, débogage USB.
- **Option** : vérification sur VirusTotal (~70 antivirus) avec une clé gratuite.

## Ce qu'il supprime
Android interdit à toute appli de supprimer une autre appli en silence. Gardien fait donc :
1. Retirer les droits administrateur (sinon la suppression est bloquée).
2. Couper l'accessibilité.
3. Lancer la désinstallation (vous confirmez d'un clic).
4. Relancer l'analyse pour vérifier.

Limite : un malware caché **dans le système** (téléphone rooté ou infecté d'usine) ne peut pas être retiré par une appli → réinitialisation complète.

## Obtenir l'APK
**Option A — GitHub (sans rien installer)**
1. Créez un dépôt GitHub et envoyez-y ce dossier.
2. Onglet **Actions** → « Compiler l'APK » se lance tout seul.
3. Téléchargez l'artefact **Gardien-apk**, installez-le sur le téléphone.

**Option B — Android Studio**
Ouvrir le dossier → bouton ▶ Run.

## Crédits
Base de détection : association Échap — github.com/AssoEchap/stalkerware-indicators (CC-BY 4.0).
