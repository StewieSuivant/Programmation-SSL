# README

## Installation des VMs

* Installer le package uml-utilities
* créer un dossier ${HOME}/AR-UML 
* décomprésser l'archive "nom archive" dans le dossier AR-UML
* récupérer les fichiers root_fs et linux
* lancer le script demo_gterm

### Modification sur le Demo Gterm

* RACINE : racine de votre UML
* UML/TEMP : localisation des données temporaire (ne pas changer)
* LINUX : localisation du linux
* DEBIAN_FS : localisation de l'image de boot
* Ne pas toucher le reste

### Les machines

* root (pas de mot de passe)
* la topologie du réseau est disponible dans le fichier config

## Programmation 

* Poodle.c : code réalisant l'algorithme utilisé pour l'attaque Poodle