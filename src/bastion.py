import paramiko
import base64
from binascii import hexlify
import socket
import threading
import sys

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
paramiko.util.log_to_file("demo_server.log")

host_key = paramiko.RSAKey(filename="test_rsa.key")
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

import re

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

class SSHServer(paramiko.ServerInterface):

    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if username in user and password == user[username]['password']:
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
                print(f"Clé publique vérifiée pour {username}")
                return paramiko.AUTH_SUCCESSFUL
        except Exception as e:
            print(f"Erreur lors de la vérification de la clé publique: {e}")
        
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
                print("(Failed to load moduli -- gex will be unsupported.)")
                raise

            transport.add_server_key(host_key)
            server = SSHServer()

            try:
                transport.start_server(server=server)
            except paramiko.SSHException:
                print("*** SSH negotiation failed.")
                sys.exit(1)

            # Ouvrir un canal de session
            channel = transport.accept(20)
            if channel is None:
                print("*** No channel.")
                sys.exit(1)
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

            channel.send(f"Veuillez selectionner un serveur entre 1 et {len(correspondance)}: ")
                         
            # Lire la sélection de l'utilisateur
            server_choice = channel.recv(1024).decode('utf-8').strip()

            channel.send(f"\r\n")

            if server_choice not in correspondance:
                channel.send("\033[91mErreur: Sélection invalide.\033[0m\r\n")
                channel.close()
                return

            # Configuration du serveur cible
            target_server = servers[correspondance[server_choice]]

            channel.send(f"Connexion au serveur {target_server['hostname']} ...\r\n")

            # Connexion au serveur cible
            target_transport = paramiko.Transport((target_server['hostname'], target_server['port']))
            target_transport.connect(username=target_server['username'], password=target_server['password'])
            target_channel = target_transport.open_session()
            target_channel.get_pty()
            target_channel.invoke_shell()

            # Transmettre les commandes et les résultats entre le client et le serveur cible
            def forward_data(source_channel, dest_channel):
                try:
                    while True:
                        data = source_channel.recv(1024)
                        if not data:
                            break
                        dest_channel.send(data)
                except Exception as e:
                    print(f"Erreur de transfert de données: {e}")
                finally:
                    source_channel.close()
                    dest_channel.close()

            # Démarrer les threads pour transmettre les données
            threading.Thread(target=forward_data, args=(channel, target_channel)).start()
            threading.Thread(target=forward_data, args=(target_channel, channel)).start()

            # Attendre la fin de la session
            target_channel.recv_exit_status()
            channel.send("\033[91mDéconnexion du serveur cible.\033[0m\r\n")
            channel.close()

        except Exception as e:
            print(f"Erreur: {e}")
        finally:
            self.client_socket.close()

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

        try:
            while True:
                client_socket, addr = server_socket.accept()
                print(f"Connexion acceptée de {addr[0]}:{addr[1]}")
                connexion = Connexion(client_socket)
                threading.Thread(target=connexion.handle_client).start()
        except Exception as e:
            print(f"Erreur: {e}")
        finally:
            server_socket.close()