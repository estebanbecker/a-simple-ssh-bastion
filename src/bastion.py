import paramiko
import base64
from binascii import hexlify
import socket
import threading
import sys
import re
import logging
import os


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

# Récupérer la clé publique de l'utilisateur
def get_public_key(public_key_file):
    try:
        with open(public_key_file, 'r') as f:
            key_data = f.read().strip()
            if key_data.startswith("ssh-rsa"):
                return paramiko.RSAKey(data=base64.b64decode(key_data.split()[1]))
            elif key_data.startswith("ssh-dss"):
                return paramiko.DSSKey(data=base64.b64decode(key_data.split()[1]))
            elif key_data.startswith("ssh-ed25519"):
                return paramiko.Ed25519Key(data=base64.b64decode(key_data.split()[1]))
            elif key_data.startswith("ecdsa-sha2-nistp256"):
                return paramiko.ECDSAKey(data=base64.b64decode(key_data.split()[1]))
    except Exception as e:
        logger.error(f"Erreur lors de la lecture de la clé publique: {e}")
        print(f"Erreur lors de la lecture de la clé publique: {e}")
        return None

def send_ascii_art(channel):
    ascii_art = """
>>=======================================================================================<<\r
||                                                                                       ||\r
||  ███████╗███████╗██╗  ██╗    ██████╗  █████╗ ███████╗████████╗██╗ ██████╗ ███╗   ██╗  ||\r
||  ██╔════╝██╔════╝██║  ██║    ██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║  ||\r
||  ███████╗███████╗███████║    ██████╔╝███████║███████╗   ██║   ██║██║   ██║██╔██╗ ██║  ||\r
||  ╚════██║╚════██║██╔══██║    ██╔══██╗██╔══██║╚════██║   ██║   ██║██║   ██║██║╚██╗██║  ||\r
||  ███████║███████║██║  ██║    ██████╔╝██║  ██║███████║   ██║   ██║╚██████╔╝██║ ╚████║  ||\r
||  ╚══════╝╚══════╝╚═╝  ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝  ||\r
||                                                                                       ||\r
>>=======================================================================================<<\r
"""
    channel.send(ascii_art + "\r\n")

def visible_length(text):
    """Calcule la longueur visible d'une chaîne en ignorant les séquences ANSI."""
    ansi_escape = re.compile(r'\033\[[0-9;]*m')  # Regex pour les séquences ANSI
    return len(ansi_escape.sub('', text))

def print_table(servers, user, channel):
    i = 1
    correspondance = {}
    header = f"{'ID':<5} | {'Hostname':<30} | {'Username':<20}\r\n"
    separator = '-' * 6 + '+' + '-' * 32 + '+' + '-' * 22 + '\r\n'
    channel.send(header)
    channel.send(separator)

    for key, value in servers.items():
        if value['groupe'] in user['esteban']['groupe']:
            hostname = f"\033[94m{value['hostname']}\033[0m"  # Bleu
            username = f"\033[92m{value['username']}\033[0m"  # Vert

            # Ajuster les largeurs en fonction de la longueur visible
            hostname_padding = 30 - visible_length(hostname)
            username_padding = 20 - visible_length(username)

            row = f"{i:<5} | {hostname}{' ' * hostname_padding} | {username}{' ' * username_padding}\r\n"
            channel.send(row)
            correspondance[str(i)] = key
            i += 1
    
    channel.send(f"\r\n")
    return correspondance

def get_user_logger(username):
    logs_dir = "./logs"
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)

    log_file = os.path.join(logs_dir, f"{username}.log")

    logger = logging.getLogger(username)
    logger.setLevel(logging.INFO)

    # Si le logger a déjà des handlers, ne pas en rajouter
    if not logger.handlers:
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger

def clean_ansi_sequences(text):
    """
    Supprime les séquences ANSI des données reçues.

    :param data: Chaîne brute contenant des séquences ANSI
    :return: Chaîne nettoyée
    """
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def process_lines(lines, user_logger, is_command_line):
    """
    Traite et journalise les lignes extraites du tampon.

    :param lines: Liste de lignes à traiter
    :param user_logger: Logger pour enregistrer les lignes
    :param is_command_line: Indicateur de traitement des commandes utilisateur
    """
    for line in lines:
        cleaned_line = line.strip()

        if cleaned_line.endswith('$') or cleaned_line.endswith('#'):
            # Une invite de commande détectée
            user_logger.info(cleaned_line)
            is_command_line = True
        elif is_command_line:
            # Ligne suivante après une commande utilisateur
            user_logger.info(cleaned_line)
            is_command_line = False
        elif cleaned_line:
            # Lignes non vides
            user_logger.info(cleaned_line)
        else:
            # Lignes vides provenant d'un fichier ou d'une commande
            user_logger.info("")


class SSHServer(paramiko.ServerInterface):

    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if username in user and password == user[username]['password']:
            logger.info(f"Authentification par mot de passe réussie pour {username}")
            print(f"Authentification par mot de passe réussie pour {username}")
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED
    
    def check_auth_publickey(self, username, key):
        key_location = './user_keys/'
        try:
            # Vérifier si l'utilisateur existe
            if username not in user:
                return paramiko.AUTH_FAILED
            
            # Construire le chemin du fichier de la clé publique
            public_key_file = key_location + user[username]['public_key_file']
            
            # Récupérer la clé publique de l'utilisateur
            stored_key = get_public_key(public_key_file)
            if stored_key is None:
                return paramiko.AUTH_FAILED
            
            # Comparer les empreintes digitales des clés
            if key.get_fingerprint() == stored_key.get_fingerprint():
                logger.info(f"Clé publique vérifiée pour {username}")
                print(f"Clé publique vérifiée pour {username}")
                return paramiko.AUTH_SUCCESSFUL
        except Exception as e:
            logger.error(f"Erreur lors de la vérification de la clé publique pour {username}: {e}") 
            print(f"Erreur lors de la vérification de la clé publique pour {username}: {e}")
        
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_with_mic(
        self, username, gss_authenticated=paramiko.AUTH_FAILED, cc_file=None
    ):
        if gss_authenticated == paramiko.AUTH_SUCCESSFUL:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_keyex(
        self, username, gss_authenticated=paramiko.AUTH_FAILED, cc_file=None
    ):
        if gss_authenticated == paramiko.AUTH_SUCCESSFUL:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def enable_auth_gssapi(self):
        return True

    def get_allowed_auths(self, username):
        return "gssapi-keyex,gssapi-with-mic,password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True


class Connexion(threading.Thread):
    def __init__(self, client_socket):
        self.client_socket = client_socket

    def handle_client(self):
        try:
            # Créer un canal SSH pour le client
            transport = paramiko.Transport(self.client_socket)
            transport.set_gss_host(socket.getfqdn(""))

            try:
                transport.load_server_moduli()
            except:
                logger.warning("Impossible de charger les moduli -- gex ne sera pas pris en charge.")
                print("(Failed to load moduli -- gex will be unsupported.)")
                raise

            transport.add_server_key(host_key)
            server = SSHServer()

            try:
                transport.start_server(server=server)
            except paramiko.SSHException as e:
                logger.error(f"Echec de la négociation SSH: {e}")
                print("*** SSH negotiation failed.")
                sys.exit(1)

            # Ouvrir un canal de session
            channel = transport.accept(20)
            if channel is None:
                logger.error("Pas de canal ouvert pour la connexion.")
                print("*** No channel.")
                sys.exit(1)
            # Authentification réussie
            username = transport.get_username()
            user_logger = get_user_logger(username)  # Initialiser le logger utilisateur
            user_logger.info(f"Authentification réussie pour {username}")
            user_logger.info(f"Utilisateur authentifié: {username}")
            print("Authenticated!")

            server.event.wait(10)

            if not server.event.is_set():
                print("*** Client never asked for a shell.")
                sys.exit(1)

            # Message de bienvenue
            send_ascii_art(channel)
            channel.send("Bienvenue sur le bastion SSH.\r\n")

            # Lister les serveurs disponibles
            channel.send("Sélectionnez un serveur:\r\n")

            correspondance = print_table(servers, user, channel)
            logger.info(f"Serveurs listés pour {username}.")

            channel.send(f"Veuillez selectionner un serveur entre 1 et {len(correspondance)}: ")
                         
            # Lire la sélection de l'utilisateur
            server_choice = channel.recv(1024).decode('utf-8').strip()
            user_logger.info(f"Sélection du serveur: {server_choice}")

            channel.send(f"\r\n")

            if server_choice not in correspondance:
                user_logger.warning(f"Sélection invalide: {server_choice}")
                channel.send("\033[91mErreur: Sélection invalide.\033[0m\r\n")
                channel.close()
                return

            # Configuration du serveur cible
            target_server = servers[correspondance[server_choice]]

            channel.send(f"Connexion au serveur {target_server['hostname']} ...\r\n")
            user_logger.info(f"Connexion au serveur {target_server['hostname']} ...")

            # Connexion au serveur cible
            target_transport = paramiko.Transport((target_server['hostname'], target_server['port']))
            target_transport.connect(username=target_server['username'], password=target_server['password'])
            target_channel = target_transport.open_session()
            target_channel.get_pty()
            target_channel.invoke_shell()

            # Transmettre les commandes et les résultats entre le client et le serveur cible
            def forward_data(source_channel, dest_channel, user_logger):
                """
                Transfère les données entre deux canaux, tout en journalisant les lignes.
                Gère les lignes inutiles et les séquences ANSI dans les données reçues.

                :param source_channel: Le canal source
                :param dest_channel: Le canal destination
                :param user_logger: Logger pour enregistrer les lignes
                """
                buffer = ""
                is_command_line = False  # Indique si la ligne provient d'une commande utilisateur

                try:
                    while True:
                        # Réception des données
                        data = source_channel.recv(1024)
                        if not data:
                            break
                        # Envoi des données au canal destination
                        dest_channel.send(data)
                        # Nettoyage des séquences ANSI et ajout au tampon
                        buffer += clean_ansi_sequences(data.decode('utf-8'))
                        # Si une nouvelle ligne est détectée, traiter les lignes accumulées
                        if '\n' in buffer:
                            lines = buffer.split('\n')
                            process_lines(lines[:-1], user_logger, is_command_line)
                            buffer = lines[-1]  # Conserver les données incomplètes
                except Exception as e:
                    error_message = f"Erreur de transfert de données: {e}"
                    print(error_message)
                    user_logger.error(error_message)
                finally:
                    source_channel.close()
                    dest_channel.close()

            # Démarrer les threads pour transmettre les données
            threading.Thread(target=forward_data, args=(channel, target_channel, user_logger)).start()
            threading.Thread(target=forward_data, args=(target_channel, channel, user_logger)).start()

            # Attendre la fin de la session
            target_channel.recv_exit_status()
            user_logger.info(f"Déconnexion du serveur cible: {target_server['hostname']}")
            channel.send("\033[91mDéconnexion du serveur cible.\033[0m\r\n")
            channel.close()

        except paramiko.SSHException as e:
            user_logger.error(f"Impossible de se connecter à {target_server['hostname']}: {e}")
            channel.send(f"Unable to connect to {target_server['hostname']}: {e}\r\n")
            channel.close()
            print(f"Erreur: {e}")
        except Exception as e:
            user_logger.error(f"Erreur: {e}")
            print(f"Erreur: {e}")
        finally:
            self.client_socket.close()
            user_logger.info("Session terminée.")
            user_logger.info("Déconnexion du client.")
            user_logger.info("Fermeture de la connexion.")

class Bastion:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def start(self):
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
                connexion = Connexion(client_socket)
                threading.Thread(target=connexion.handle_client).start()
        except Exception as e:
            print(f"Erreur serveur: {e}")
            logger.error(f"Erreur serveur: {e}")
        finally:
            server_socket.close()
            logger.info("Serveur arrêté.")