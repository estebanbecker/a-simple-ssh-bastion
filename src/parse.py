import json

def parse_config(config_file):
    # Charger le fichier JSON
    with open(config_file, 'r') as f:
        data = json.load(f)
    
    # Parcourir les utilisateurs et afficher leurs informations
    for user in data['users']:
        username = user['username']
        password = user['password']
        role = user['role']
        print(f"Username: {username}, Password: {password}, Role: {role}")

    # Parcourir les serveurs et afficher leurs informations
    for servers in data['servers']:
        destination = servers['destination']
        port = servers['port']
        print(f"Destination: {destination}, Port: {port}")
    

if __name__ == '__main__':
    config_file = './src/config.json'
    config = parse_config(config_file)
