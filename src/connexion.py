import paramiko
import logging
import threading
import socket
from SSHServer import SSHServer
import sys
import os
import re
import base64
from aes_logging import *


class Connexion(threading.Thread):
    """
    Gère la connexion SSH avec un client.
    """
    def __init__(self, client_socket, logger,host_key, servers, users):
        """
        Constructeur de la classe Connexion
        client_socket: Socket client
        logger: Objet logger pour journaliser les événements
        host_key: Clé RSA du serveur
        """
        self.client_socket = client_socket
        self.logger = logger
        self.logger_encryption_key = load_aes_key()
        self.host_key = host_key
        self.servers = servers
        self.users = users

    def handle_client(self):
        """
        Gère la connexion SSH avec un client.
        """
        try:
            # Créer un canal SSH pour le client
            transport = paramiko.Transport(self.client_socket)
            transport.set_gss_host(socket.getfqdn(""))

            try:
                transport.load_server_moduli()
            except:
                push_log_entry(self.logger, 'warning', "Impossible de charger les moduli -- gex ne sera pas pris en charge.", self.logger_encryption_key)
                print("(Failed to load moduli -- gex will be unsupported.)")
                raise

            transport.add_server_key(self.host_key)
            server = SSHServer(self.logger, self.users)

            try:
                transport.start_server(server=server)
            except paramiko.SSHException as e:
                push_log_entry(self.logger, 'error', f"Echec de la négociation SSH: {e}", self.logger_encryption_key)
                print("*** SSH negotiation failed.")
                sys.exit(1)

            # Ouvrir un canal de session
            channel = transport.accept(20)
            if channel is None:
                push_log_entry(self.logger, 'error', "Pas de canal ouvert pour la connexion.", self.logger_encryption_key)
                print("*** No channel.")
                sys.exit(1)
            # Authentification réussie
            username = transport.get_username()
            user_logger = self.get_user_logger(username)  # Initialiser le logger utilisateur
            push_log_entry(user_logger, 'info', f"Authentification réussie pour {username}", self.logger_encryption_key)
            push_log_entry(user_logger, 'info', f"Utilisateur authentifié: {username}", self.logger_encryption_key)
            print("Authenticated!")

            server.event.wait(10)

            if not server.event.is_set():
                print("*** Client never asked for a shell.")
                sys.exit(1)

            # Message de bienvenue
            self.send_ascii_art(channel)
            channel.send("Bienvenue sur le bastion SSH.\r\n")

            # Lister les serveurs disponibles
            channel.send("Sélectionnez un serveur:\r\n")

            correspondance = self.print_table(self.servers, self.users, channel)
            push_log_entry(self.logger, 'info', f"Serveurs listés pour {username}.", self.logger_encryption_key)

            target_channel = None

            while target_channel is None:
                    
                # Demander à l'utilisateur de sélectionner un serveur
                server_choice = None
                while server_choice not in correspondance:
                    channel.send(f"Veuillez selectionner un serveur entre 1 et {len(correspondance)} ou exit: ")
                                
                    # Lire la sélection de l'utilisateur
                    server_choice = self.lire_entree_utilisateur(channel)
                    push_log_entry(user_logger, 'info', f"Sélection du serveur: {server_choice}", self.logger_encryption_key)

                    if server_choice == "exit":
                        channel.send("Déconnexion...\r\n")
                        push_log_entry(user_logger, 'info', "Déconnexion du client.", self.logger_encryption_key)
                        return
                    elif server_choice not in correspondance:
                        channel.send(f"\r\n")
                        push_log_entry(user_logger, 'warning', f"Sélection invalide: {server_choice}", self.logger_encryption_key)
                        channel.send("\033[91mErreur: Sélection invalide.\033[0m\r\n")

                # Configuration du serveur cible
                target_server = self.servers[correspondance[server_choice]]

                channel.send(f"Connexion au serveur {target_server['hostname']} ...\r\n")
                push_log_entry(user_logger, 'info', f"Connexion au serveur {target_server['hostname']} ...", self.logger_encryption_key)

                # Se connecter au serveur cible
                try:
                    target_channel = self.connect_to_server(target_server, channel)
                    push_log_entry(user_logger, 'info', f"Connecté à {target_server['hostname']}", self.logger_encryption_key)
                    channel.send(f"Connecté à {target_server['hostname']}\r\n")
                except Exception as e:
                    push_log_entry(user_logger, 'error', f"Impossible de se connecter à {target_server['hostname']}: {e}", self.logger_encryption_key)
                    channel.send(f"Impossible de se connecter à {target_server['hostname']}: {e}\r\n")
                    return


            # Démarrer les threads pour transmettre les données
            threading.Thread(target=self.forward_data, args=(channel, target_channel, user_logger, self.logger_encryption_key)).start()
            threading.Thread(target=self.forward_data, args=(target_channel, channel, user_logger, self.logger_encryption_key)).start()

            # Attendre la fin de la session
            target_channel.recv_exit_status()
            push_log_entry(user_logger, 'info', f"Déconnexion du serveur cible: {target_server['hostname']}", self.logger_encryption_key)
            channel.close()

        except paramiko.SSHException as e:
            push_log_entry(self.logger, 'error', f"Impossible de se connecter à {target_server['hostname']}: {e}", self.logger_encryption_key)
            channel.send(f"Unable to connect to {target_server['hostname']}: {e}\r\n")
            channel.close()
            print(f"Erreur: {e}")
        except Exception as e:
            try:
                push_log_entry(user_logger, 'error', f"Erreur: {e}", self.logger_encryption_key)
                channel.send(f"Erreur: {e}\r\n")
            except UnboundLocalError as e2:
                print("♦"*50)
                print(f"C'est pas grave, voici l'erreur : {e2}")
                print("♦"*50)
            # print(f"Erreur: {e}")
        finally:
            try:
                push_log_entry(user_logger, 'info', "Session terminée.", self.logger_encryption_key)
                push_log_entry(user_logger, 'info', "Déconnexion du client.", self.logger_encryption_key)
                push_log_entry(user_logger, 'info', "Fermeture de la connexion.", self.logger_encryption_key)
            except UnboundLocalError as e:
                print("☻"*50)
                print(f"C'est pas grave, voici l'erreur : {e}")
                print("☻"*50)
            self.client_socket.close()

    def lire_entree_utilisateur(self,channel,show=True):
        """
        Lit l'entrée utilisateur et renvoie la sélection du serveur.
        channel: Canal de communication avec le client
        """
        server_choice = ""
        while True:
            char = channel.recv(1).decode('utf-8')
            if char == '\r':  # Détecter le retour à la ligne
                break
            elif char == '\x7f':  # Gestion du backspace
                if len(server_choice) > 0:
                    server_choice = server_choice[:-1]
                    if show:
                        channel.send('\b \b')
            else:
                server_choice += char
                if show:
                    channel.send(char)
        channel.send('\r\n')
        return server_choice

    # Transmettre les commandes et les résultats entre le client et le serveur cible
    def forward_data(self, source_channel, dest_channel, user_logger, encryption_key):
        """
        Transfère les données entre deux canaux, tout en journalisant les lignes.
        Gère les lignes inutiles et les séquences ANSI dans les données reçues.

        :param source_channel: Le canal source
        :param dest_channel: Le canal destination
        :param user_logger: Logger pour enregistrer les lignes
        """
        buffer = ""

        try:
            while True:
                # Réception des données
                data = source_channel.recv(1024)
                if not data:
                    break
                # Envoi des données au canal destination
                dest_channel.send(data)
                # Nettoyage des séquences ANSI et ajout au tampon
                buffer += self.clean_ansi_sequences(data.decode('utf-8'))
                # Si une nouvelle ligne est détectée, traiter les lignes accumulées
                if '\n' in buffer:
                    lines = buffer.split('\n')
                    self.process_lines(lines[:-1], user_logger, encryption_key)
                    buffer = lines[-1]  # Conserver les données incomplètes
        except Exception as e:
            push_log_entry(user_logger, 'error', f"Erreur de transfert de données: {e}", encryption_key)
            print(f"Erreur de transfert de données: {e}")
        finally:
            try:
                source_channel.close()
            except:
                pass
            try:
                dest_channel.close()
            except:
                pass

    def connect_to_server(self,target_server, channel):
        """
        Se connecte au serveur cible et renvoie le canal de communication.
        target_server: Dictionnaire de configuration du serveur cible
        channel: Canal de communication avec le client
        """
        # Connexion au serveur cible
        target_transport = paramiko.Transport((target_server['hostname'], target_server['port']))
        target_transport.start_client()

        # Check host key
        server_key = target_transport.get_remote_server_key()
        public_key_location = "server_public_keys/"
        public_key_file = os.path.join(public_key_location, str(target_server['hostname']) + "-" + str(target_server['port']) + ".pub")
        #check if the folder exist
        if not os.path.exists(public_key_location):
            os.makedirs(public_key_location)
        if not os.path.exists(public_key_file):
            # Save the server public key
            with open(public_key_file, 'wb') as file:
                # Save the server public key with the correct format
                if isinstance(server_key, paramiko.RSAKey):
                    file.write(f"ssh-rsa {base64.b64encode(server_key.asbytes()).decode()}\r\n".encode())
                elif isinstance(server_key, paramiko.DSSKey):
                    file.write(f"ssh-dss {base64.b64encode(server_key.asbytes()).decode()}\r\n".encode())
                elif isinstance(server_key, paramiko.Ed25519Key):
                    file.write(f"ssh-ed25519 {base64.b64encode(server_key.asbytes()).decode()}\r\n".encode())
                elif isinstance(server_key, paramiko.ECDSAKey):
                    file.write(f"ecdsa-sha2-nistp256 {base64.b64encode(server_key.asbytes()).decode()}\r\n".encode())
        else:
            # Compare the server public key with the saved key
            with open(public_key_file, 'rb') as file:
                key_data = file.read().strip()
                if key_data.startswith(b"ssh-rsa"):
                    saved_key = paramiko.RSAKey(data=base64.b64decode(key_data.split()[1]))
                elif key_data.startswith(b"ssh-dss"):
                    saved_key = paramiko.DSSKey(data=base64.b64decode(key_data.split()[1]))
                elif key_data.startswith(b"ssh-ed25519"):
                    saved_key = paramiko.Ed25519Key(data=base64.b64decode(key_data.split()[1]))
                elif key_data.startswith(b"ecdsa-sha2-nistp256"):
                    saved_key = paramiko.ECDSAKey(data=base64.b64decode(key_data.split()[1]))
                if server_key.get_fingerprint() != saved_key.get_fingerprint():
                    channel.send("\033[91mClé publique du serveur inconnue. Connection refusé. Veuillez contacter un administrateur\033[0m\r\n")
                    raise Exception("Clé publique du serveur "+str(target_server['hostname'])+":"+str(target_server['port'])+" inconnue.")


        try:
            if 'private_key_file' in target_server and target_server['private_key_file']!= None:
                # Authentification par clé privée
                private_key_file = target_server['private_key_file']
                self.location_private_key = "server_connection_keys/"
                
                private_key_file = os.path.join(self.location_private_key, private_key_file)
                # Charger la clé privée
                try:
                    private_key = paramiko.RSAKey.from_private_key_file(private_key_file)
                except paramiko.ssh_exception.PasswordRequiredException:
                    # Demander le mot de passe de la clé privée
                    test = 0
                    correct_password = False
                    while not correct_password and test < 3:
                        test += 1
                        channel.send("Mot de passe de la clé privée: ")
                        private_key_password = self.lire_entree_utilisateur(channel, False)
                        try:
                            private_key = paramiko.RSAKey.from_private_key_file(private_key_file, password=private_key_password)
                            correct_password = True
                        # Si le mot de passe est incorrect
                        except paramiko.ssh_exception.SSHException as e:
                            channel.send(f"Mot de passe incorrect: {e}\r\n")

                
                #Si la clé privée n'est pas au format RSA, essayer avec une clé DSA
                except paramiko.ssh_exception.SSHException:
                    try:
                        private_key = paramiko.DSSKey.from_private_key_file(private_key_file)
                    except paramiko.ssh_exception.PasswordRequiredException:
                        # Demander le mot de passe de la clé privée
                        test = 0
                        correct_password = False
                        while not correct_password and test < 3:
                            test += 1
                            channel.send("Mot de passe de la clé privée: ")
                            private_key_password = self.lire_entree_utilisateur(channel, False)
                            try:
                                private_key = paramiko.DSSKey.from_private_key_file(private_key_file, password=private_key_password)
                                correct_password = True
                            # Si le mot de passe est incorrect
                            except paramiko.ssh_exception.SSHException as e:
                                channel.send(f"Mot de passe incorrect: {e}\r\n")
                                raise Exception(f"Mot de passe incorrect: {e}")
                    #Si la clé privée n'est pas au format DSA, essayer avec une clé ECDSA
                    except paramiko.ssh_exception.SSHException:
                        try:
                            private_key = paramiko.ECDSAKey.from_private_key_file(private_key_file)
                        except paramiko.ssh_exception.PasswordRequiredException:
                            # Demander le mot de passe de la clé privée
                            test = 0
                            correct_password = False
                            while not correct_password and test < 3:
                                test += 1
                                channel.send("Mot de passe de la clé privée: ")
                                private_key_password = self.lire_entree_utilisateur(channel, False)
                                try:
                                    private_key = paramiko.ECDSAKey.from_private_key_file(private_key_file, password=private_key_password)
                                    correct_password = True
                                # Si le mot de passe est incorrect
                                except paramiko.ssh_exception.SSHException as e:
                                    channel.send(f"Mot de passe incorrect: {e}\r\n")
                                    raise Exception(f"Mot de passe incorrect: {e}")

                target_transport.auth_publickey(username=target_server['username'], key=private_key)
            else:
                # Authentification par mot de passe
                target_transport.auth_password(username=target_server['username'], password=target_server['password'])      

        except paramiko.ssh_exception.AuthenticationException as e:
            raise Exception(f"Erreur d'authentification: {e}")  
        
        # Check host key
        server_key = target_transport.get_remote_server_key()


        target_channel = target_transport.open_session()
        target_channel.get_pty()
        target_channel.invoke_shell()

        return target_channel

    def get_user_logger(self,username):
        """
        Récupère un logger pour un utilisateur donné.
        username: Nom d'utilisateur
        """
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
    
    def send_ascii_art(self, channel):
        """
        Envoie un art ASCII au client.
        channel: Canal de communication avec le client
        """

        ascii_art = """
    >>=======================================================================================<<\r
    ||                                                                                       ||\r
    ||  \033[31m███████╗███████╗██╗  ██╗    ██████╗  █████╗ ███████╗████████╗██╗ ██████╗ ███╗   ██╗  \033[0m||\r
    ||  \033[38;5;208m██╔════╝██╔════╝██║  ██║    ██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║  \033[0m||\r
    ||  \033[33m███████╗███████╗███████║    ██████╔╝███████║███████╗   ██║   ██║██║   ██║██╔██╗ ██║  \033[0m||\r
    ||  \033[32m╚════██║╚════██║██╔══██║    ██╔══██╗██╔══██║╚════██║   ██║   ██║██║   ██║██║╚██╗██║  \033[0m||\r
    ||  \033[34m███████║███████║██║  ██║    ██████╔╝██║  ██║███████║   ██║   ██║╚██████╔╝██║ ╚████║  \033[0m||\r
    ||  \033[35m╚══════╝╚══════╝╚═╝  ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝  \033[0m||\r
    ||                                                                                       ||\r
    >>=======================================================================================<<\r
    """
        channel.send(ascii_art + "\r\n")


    def print_table(self, servers, user, channel):
        """
        Affiche un tableau de serveurs disponibles pour l'utilisateur.
        servers: Dictionnaire de serveurs
        user: Dictionnaire d'utilisateurs
        channel: Canal de communication avec le client
        """
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
                hostname_padding = 30 - self.visible_length(hostname)
                username_padding = 20 - self.visible_length(username)

                row = f"{i:<5} | {hostname}{' ' * hostname_padding} | {username}{' ' * username_padding}\r\n"
                channel.send(row)
                correspondance[str(i)] = key
                i += 1
        
        channel.send(f"\r\n")
        return correspondance
    
    def clean_ansi_sequences(self, text):
        """
        Supprime les séquences ANSI des données reçues.

        :param data: Chaîne brute contenant des séquences ANSI
        :return: Chaîne nettoyée
        """
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)
    
    def process_lines(self,lines, user_logger, encryption_key):
        """
        Traite et journalise les lignes extraites du tampon.

        :param lines: Liste de lignes à traiter
        :param user_logger: Logger pour enregistrer les lignes
        """
        for line in lines:
            cleaned_line = line.strip()

            if cleaned_line:
                # Lignes non vides
                push_log_entry(user_logger, 'info', cleaned_line, encryption_key)
            else:
                # Lignes vides provenant d'un fichier ou d'une commande
                push_log_entry(user_logger, 'info', "", encryption_key)

    def visible_length(self,text):
        """Calcule la longueur visible d'une chaîne en ignorant les séquences ANSI."""
        ansi_escape = re.compile(r'\033\[[0-9;]*m')  # Regex pour les séquences ANSI
        return len(ansi_escape.sub('', text))