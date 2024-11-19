from binascii import hexlify
import socket
import threading
import sys
import logging
from connexion import Connexion
import paramiko


# Configuration des serveurs cibles
servers = {
    '1': {'hostname': '127.0.0.1', 'username': 'user', 'password': 'password', 'port': 2200, 'groupe': '1'},
    '2': {'hostname': 'server2.example.com', 'username': 'user2', 'password': 'password2', 'port': 2200, 'groupe': '2'},
    '3': {'hostname': 'server3.example.com', 'username': 'user3', 'password': 'password3', 'port': 2200, 'groupe': '3'},
    '4': {'hostname': 'server4.example.com', 'username': 'user4', 'password': 'password4', 'port': 2200, 'groupe': '4'},
}

user = {
    'esteban': {'password': 'password', 'public_key_file': 'esteban.pub', 'groupe': ['1', '2']},
    'user2': {'password': 'password2', 'public_key_file': None, 'groupe': ['2', '3']},
}

# setup logging
# paramiko.util.log_to_file("demo_server.log")
# Configuration de la journalisation globale
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bastion.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("BastionSSH")


host_key = paramiko.RSAKey(filename="test_rsa.key")
logger.info("Read key: %s", hexlify(host_key.get_fingerprint()))
# host_key = paramiko.DSSKey(filename='test_dss.key')

print("Read key: " + str(hexlify(host_key.get_fingerprint())))

class Bastion:
    def __init__(self, host, port):
        self.host = host
        self.port = port

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
        logger.info(f"Bastion SSH en écoute sur {self.host}:{self.port}")

        try:
            while True:
                client_socket, addr = server_socket.accept()
                print(f"Connexion acceptée de {addr[0]}:{addr[1]}")
                logger.info(f"Connexion acceptée de {addr[0]}:{addr[1]}")   
                connexion = Connexion(client_socket, logger, host_key, servers, user)
                threading.Thread(target=connexion.handle_client).start()
        except Exception as e:
            print(f"Erreur serveur: {e}")
            logger.error(f"Erreur serveur: {e}")
        finally:
            server_socket.close()
            logger.info("Serveur arrêté.")

