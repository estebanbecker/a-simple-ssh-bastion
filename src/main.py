import paramiko
import base64
from binascii import hexlify
import sys
import socket
import threading
import os
import logging

# Activer le mode de débogage pour paramiko
logging.basicConfig(level=logging.DEBUG)
paramiko.util.log_to_file('paramiko.log')

# Configuration des serveurs cibles
servers = {
    '3': {'hostname': 'server3.example.com', 'username': 'user3', 'password': 'password3', 'port': 22},
    '4': {'hostname': 'server4.example.com', 'username': 'user4', 'password': 'password4', 'port': 22},
}

# setup logging
paramiko.util.log_to_file("demo_server.log")

host_key = paramiko.RSAKey(filename="test_rsa.key")
# host_key = paramiko.DSSKey(filename='test_dss.key')

print("Read key: " + str(hexlify(host_key.get_fingerprint())))

class SSHServer(paramiko.ServerInterface):
    data = (
        b"AAAAB3NzaC1yc2EAAAABIwAAAIEAyO4it3fHlmGZWJaGrfeHOVY7RWO3P9M7hp"
        b"fAu7jJ2d7eothvfeuoRFtJwhUmZDluRdFyhFY/hFAh76PJKGAusIqIQKlkJxMC"
        b"KDqIexkgHAfID/6mqvmnSJf0b5W8v5h2pI/stOSwTQ+pxVhwJ9ctYDhRSlF0iT"
        b"UWT10hcuO4Ks8="
    )
    good_pub_key = paramiko.RSAKey(data=base64.b64decode(data))

    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if (username == "robey") and (password == "foo"):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        print("Auth attempt with key: " + str(hexlify(key.get_fingerprint())))
        if (username == "robey") and (key == self.good_pub_key):
            return paramiko.AUTH_SUCCESSFUL
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


def handle_client(client_socket):
    try:
        # Créer un canal SSH pour le client
        transport = paramiko.Transport(client_socket)
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

        channel.send("\r\n\r\nWelcome to my dorky little BBS!\r\n\r\n")

        # Afficher le menu de sélection des serveurs
        channel.send("Bienvenue sur le bastion SSH. Veuillez sélectionner un serveur (1, 2, 3, 4): \r\n")

        # Lire la sélection de l'utilisateur
        server_choice = channel.recv(1024).decode('utf-8').strip()

        if server_choice not in servers:
            channel.send("Sélection invalide. Déconnexion.\r\n")
            channel.close()
            return

        # Configuration du serveur cible
        target_server = servers[server_choice]

        channel.send(f"Connexion au serveur {target_server['hostname']} ...\r\n")

        # Connexion au serveur cible
        target_transport = paramiko.Transport((target_server['hostname'], target_server['port']))
        channel.send(f"Authentification au serveur {target_server['hostname']} ...\r\n")
        target_transport.connect(username=target_server['username'], password=target_server['password'])
        channel.send(f"Connecté au serveur {target_server['hostname']} ...\r\n")
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

        # Wait for the channel to close
        target_channel.recv_exit_status()
        channel.close()

    except Exception as e:
        print(f"Erreur: {e}")
    finally:
        client_socket.close()

def start_bastion(host, port):
    # Créer un socket serveur
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)

    print(f"Bastion SSH en écoute sur {host}:{port}")

    try:
        while True:
            client_socket, addr = server_socket.accept()
            print(f"Connexion acceptée de {addr[0]}:{addr[1]}")
            threading.Thread(target=handle_client, args=(client_socket,)).start()
    except Exception as e:
        print(f"Erreur: {e}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_bastion('0.0.0.0', 2222)