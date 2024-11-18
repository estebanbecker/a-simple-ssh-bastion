import bcrypt
import json

def change_password(config_file_path):
    # Charger le fichier JSON
    with open(config_file_path, 'r') as f:
        config = json.load(f)

    username = input("Enter the username: ")
    
    # Chercher l'utilisateur dans la liste
    user_found = False
    for user in config['users']:
        if user['username'] == username:
            user_found = True
            password = input("Enter the new password: ")
            user['password'] = hash_password(password)
            break
    
    if not user_found:
        print("User not found.")
    else:
        # Enregistrer les modifications dans le fichier JSON
        with open(config_file_path, 'w') as f:
            json.dump(config, f, indent=4)
        print("Password changed successfully.")

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
if __name__ == '__main__':
    conf = './src/config.json'
    change_password(conf)