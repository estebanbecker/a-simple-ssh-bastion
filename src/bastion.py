from binascii import hexlify
import socket
import threading
import sys
import logging
from connexion import Connexion
import paramiko
import os
from aes_logging import *
from parse import parse_servers, parse_user



class Bastion:

    # Configuration des serveurs cibles
    servers = parse_servers("./src/config.json")

    # Configuration des utilisateurs
    user = parse_user("./src/config.json")

    def __init__(self, host, port):
        """
        Constructeur de la classe Bastion
        host: Adresse IP du serveur bastion
        port: Port du serveur bastion
        """
        self.host = host
        self.port = port

        #check if the logs directory exists, if not create it
        if not os.path.exists('./logs'):
            os.makedirs('./logs')
        

        # Configuration de la journalisation globale
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler("./logs/BASTION.log"),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger("BastionSSH")
        self.logger_encryption_key = load_aes_key()
        # Désactiver les logs de Paramiko
        logging.getLogger("paramiko").setLevel(logging.CRITICAL)

        # Charger ou générer la clé hôte
        self.load_or_generate_host_key()

    def load_or_generate_host_key(self):
        """
        Charger la clé hôte si elle existe, sinon en générer une nouvelle
        """
        key_filename = "test_rsa.key"

        # Vérifier si le fichier de clé existe
        if not os.path.exists(key_filename):
            # Générer une nouvelle clé RSA
            self.host_key = paramiko.RSAKey.generate(2048)
            # Sauvegarder la clé dans un fichier
            self.host_key.write_private_key_file(key_filename)
            push_log_entry(self.logger, 'info', f"Generated new RSA key and saved to {key_filename}", self.logger_encryption_key)
        else:
            # Charger la clé existante
            self.host_key = paramiko.RSAKey(filename=key_filename)
            push_log_entry(self.logger, 'info', f"Read key: {hexlify(self.host_key.get_fingerprint())}", self.logger_encryption_key)

        print("Read key: " + str(hexlify(self.host_key.get_fingerprint())))

    def start(self):
        """
        Démarrer le serveur bastion SSH
        """
        # Créer un socket serveur
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)

        print(f"Bastion SSH en écoute sur {self.host}:{self.port}")
        push_log_entry(self.logger, 'info', f"Bastion SSH en écoute sur {self.host}:{self.port}", self.logger_encryption_key)

        try:
            while True:
                client_socket, addr = server_socket.accept()
                print(f"Connexion acceptée de {addr[0]}:{addr[1]}")
                push_log_entry(self.logger, 'info', f"Connexion acceptée de {addr[0]}:{addr[1]}", self.logger_encryption_key)
                connexion = Connexion(client_socket, self.logger, self.host_key, self.servers, self.user)
                threading.Thread(target=connexion.handle_client).start()
        except Exception as e:
            print(f"Erreur serveur: {e}")
            push_log_entry(self.logger, 'error', f"Erreur serveur: {e}", self.logger_encryption_key)
        finally:
            server_socket.close()
            push_log_entry(self.logger, 'critical', "Serveur arrêté.", self.logger_encryption_key)

