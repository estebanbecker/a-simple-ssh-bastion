# A Simple SSH Bastion

## Description
Ce projet fournit une configuration simple pour un bastion SSH. Un bastion SSH est un serveur intermédiaire utilisé pour accéder à des serveurs privés situés derrière un pare-feu. Ce projet à été dans le cadre d'un projet universitaire et n'est pas penséé pour un déploiement en raison de gros manquements en terme de sécurité et du non.

## Prérequis
- Un serveur Debian
- Accès root ou sudo

## Installation
1. Lancer le serveur via Docker :
    ```bash
    docker run -d -p 2222:2222 --name ssh-bastion -v ./config:/app/config -v ./server_connection_keys:/app/server_connection_keys -v ./user_keys:/app/user_keys -v ./logs:/app/logs monsieurplacard/a-simple-ssh-bastion
    ```

## Configuration
1. Modifiez le fichier de configuration `sshd_config` selon vos besoins. Voir le fichier [example_config.json](example_config.json) pour un exemple.

## Utilisation
Pour vous connecter à un serveur privé via le bastion SSH, utilisez la commande suivante :
```bash
ssh user@bastion_server -p 2222
```

## Contribuer
Les contributions sont les bienvenues ! Veuillez soumettre une pull request ou ouvrir une issue pour discuter des changements que vous souhaitez apporter.

## Licence
Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.
