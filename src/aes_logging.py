from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import os
import re


def generate_and_save_aes_key(file_path='logs/aes_key.key', key_size=256):
    """
    Génère une clé AES de key_size bits et la sauvegarde dans un fichier.
    
    :param file_path: Chemin du fichier où sauvegarder la clé (par défaut : 'logs/aes_key.key')
    :param key_size: Taille de la clé en bits (par défaut : 256)
    """
    # Vérifier que la taille de la clé est valide
    if key_size not in [128, 192, 256]:
        raise ValueError("La taille de la clé doit être 128, 192 ou 256 bits")
    
    # Générer une clé AES de key_size bits
    key = os.urandom(key_size // 8)  # key_size bits = key_size // 8 octets
    print(f"Clé AES: {key}")

    # Encoder la clé en base64 pour une meilleure lisibilité et stockage
    key_base64 = base64.b64encode(key).decode('utf-8')

    print(f"Clé AES de {key_size} bits (encodée en base64) : {key_base64}")

    # Sauvegarder la clé dans un fichier
    with open(file_path, 'w') as f:
        f.write(key_base64)

def load_aes_key(file_path='logs/aes_key.key'):
    """
    Charge une clé AES depuis un fichier.
    
    :param file_path: Chemin du fichier où charger la clé (par défaut : 'logs/aes_key.key')
    :return: Clé AES chargée
    """
    # Vérifier que le fichier existe
    if not os.path.exists(file_path):
        generate_and_save_aes_key(file_path)

    # Lire la clé depuis le fichier
    with open(file_path, 'r') as f:
        key_base64 = f.read().strip()

    # Décoder la clé depuis base64
    key = base64.b64decode(key_base64.encode('utf-8'))

    return key

def encrypt_log_entry(data, key):
    """
    Chiffre une entrée de log avec AES.

    :param data: Données à chiffrer
    :param key: Clé de chiffrement
    :return: Données chiffrées
    """
    # Générer un IV (vecteur d'initialisation)
    iv = os.urandom(16)  # 16 octets pour AES

    # Créer un chiffreur AES en mode GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Ajouter un padding PKCS7
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Chiffrer les données
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Retourner les données chiffrées avec l'IV et le tag
    return iv + encryptor.tag + encrypted_data

def push_log_entry(logger, log_type, data, key):
    """
    Chiffre et enregistre une entrée de log dans un fichier de log.
    
    :param logger: Instance du logger
    :param log_type: Type de log (info, warning, error)
    :param data: Données à enregistrer
    :param key: Clé de chiffrement
    """
    encrypted_data = encrypt_log_entry(data.encode('utf-8'), key)
    encoded_encrypted_data = base64.b64encode(encrypted_data).decode('utf-8')

    # Log the encrypted data according to the log type
    if log_type == 'info':
        logger.info(f"{encoded_encrypted_data}")
    elif log_type == 'warning':
        logger.warning(f"{encoded_encrypted_data}")
    elif log_type == 'error':
        logger.error(f"{encoded_encrypted_data}")
    elif log_type == 'critical':
        logger.critical(f"{encoded_encrypted_data}")
    elif log_type == 'debug':
        logger.debug(f"{encoded_encrypted_data}")
    else:
        logger.info(f"{encoded_encrypted_data}")

def decrypt_log_entry(encrypted_data, key):
    """
    Déchiffre une entrée de log avec AES.

    :param encrypted_data: Données chiffrées
    :param key: Clé de chiffrement
    :return: Données déchiffrées
    """
    # Extraire l'IV (vecteur d'initialisation) et le tag
    iv = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]

    # Créer un déchiffreur AES en mode GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    # Déchiffrer les données
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Supprimer le padding PKCS7
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data

def decrypt_log_file(input_file, output_file, key):
    """
    Déchiffre un fichier de log contenant des entrées chiffrées.

    :param input_file: Chemin du fichier de log chiffré
    :param output_file: Chemin du fichier de log déchiffré
    :param key: Clé de chiffrement
    """
    with open(input_file, 'r') as f_in, open(output_file, 'w') as f_out:
        for line in f_in:
            # Rechercher les parties chiffrées
            match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})( - .*){0,2} - (.*)", line)
            if match:
                timestamp = match.group(1)
                if match.group(2):
                    # on est dans le cas : %(asctime)s - %(name)s - %(levelname)s - %(message)s
                    # le groupe2 contient : " - %(name)s - %(levelname)s"
                    encrypted_data = base64.b64decode(match.group(3))
                    decrypted_data = decrypt_log_entry(encrypted_data, key)
                    f_out.write(f"{timestamp}{match.group(2)} - {decrypted_data.decode('utf-8')}\n")
                else:
                    encrypted_data = base64.b64decode(match.group(3))
                    decrypted_data = decrypt_log_entry(encrypted_data, key)
                    f_out.write(f"{timestamp} - {decrypted_data.decode('utf-8')}\n")
            else:
                f_out.write(line)


if __name__ == '__main__':
    key = load_aes_key()

    # décrypte tous les fichiers dans le dossier logs
    for file in os.listdir('./logs'):
        if file.endswith('.log') and not file.startswith('decrypted_'):
            decrypt_log_file(f'./logs/{file}', f'./logs/decrypted_{file}', key)
            # afficher phrase de confirmation avec le chemin du fichier de log
            print(f"Fichier ./logs/{file} déchiffré avec succès !")

    print("Tous les fichiers de log ont été déchiffrés avec succès !")