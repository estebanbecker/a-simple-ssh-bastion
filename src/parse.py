import json

def parse_user(file_path):
    try:
        # Charger les données JSON depuis le fichier
        with open(file_path, 'r') as file:
            data = json.load(file)
        
        # Créer un dictionnaire pour les utilisateurs
        users = {}
        for user in data.get("users", []):
            username = user.get("username")
            if username:  # Vérifier si le champ 'username' existe
                users[username] = {
                    "password": user.get("password", ""),  # Mot de passe ou chaîne vide par défaut
                    "public_key_file": user.get("ssh_key", None),  # Remplacer les absences par None
                    "groupe": user.get("groups", [])  # Listes de groupes par défaut
                }
        
        return users
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Erreur lors du traitement du fichier : {e}")
        return {}

def parse_servers(file_path):
    try:
        # Charger les données JSON depuis le fichier
        with open(file_path, 'r') as file:
            data = json.load(file)
        
        # Récupérer les serveurs et les transformer en dictionnaire
        servers = data.get("servers", [])
        servers_dict = {
            server.get("id"): {
                "hostname": server.get("destination"),
                "port": server.get("port", 2200),  # Port par défaut si non spécifié
                "username": server.get("username"),
                "password": server.get("password"),
                "groupe": server.get("group"),
                "private_key_file": server.get("private_key")
            }
            for server in servers
        }
        
        return servers_dict
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Erreur lors du traitement du fichier : {e}")
        return {}
    

if __name__ == '__main__':
    # Analyse de la partie 'users' du fichier de configuration
    config_user = parse_user("./src/config/config.json")
    result = json.dumps(config_user, indent=4) # Convertir le dictionnaire en chaîne JSON
    print(result)

    # Analyse de la partie 'servers' du fichier de configuration
    config_server = parse_servers("./src/config/config.json")
    result = json.dumps(config_server, indent=4) # Convertir le dictionnaire en chaîne JSON
    print(result)
