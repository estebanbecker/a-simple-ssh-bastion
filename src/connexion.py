import paramiko
import logging
import threading
import socket
from SSHServer import SSHServer
import sys
import os
import re


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
                self.logger.warning("Impossible de charger les moduli -- gex ne sera pas pris en charge.")
                print("(Failed to load moduli -- gex will be unsupported.)")
                raise

            transport.add_server_key(self.host_key)
            server = SSHServer(self.logger, self.users)

            try:
                transport.start_server(server=server)
            except paramiko.SSHException as e:
                self.logger.error(f"Echec de la négociation SSH: {e}")
                print("*** SSH negotiation failed.")
                sys.exit(1)

            # Ouvrir un canal de session
            channel = transport.accept(20)
            if channel is None:
                self.logger.error("Pas de canal ouvert pour la connexion.")
                print("*** No channel.")
                sys.exit(1)
            # Authentification réussie
            username = transport.get_username()
            user_logger = self.get_user_logger(username)  # Initialiser le logger utilisateur
            user_logger.info(f"Authentification réussie pour {username}")
            user_logger.info(f"Utilisateur authentifié: {username}")
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
            self.logger.info(f"Serveurs listés pour {username}.")

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
            target_server = self.servers[correspondance[server_choice]]

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
                        buffer += self.clean_ansi_sequences(data.decode('utf-8'))
                        # Si une nouvelle ligne est détectée, traiter les lignes accumulées
                        if '\n' in buffer:
                            lines = buffer.split('\n')
                            self.process_lines(lines[:-1], user_logger, is_command_line)
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

    def get_user_logger(self,username):
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
    
    def send_ascii_art(self,channel):
            """
            Envoie un art ASCII au client.
            channel: Canal de communication avec le client
            """

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

    def print_table(self, servers, user, channel):
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
    
    def process_lines(self,lines, user_logger, is_command_line):
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

    def visible_length(self,text):
        """Calcule la longueur visible d'une chaîne en ignorant les séquences ANSI."""
        ansi_escape = re.compile(r'\033\[[0-9;]*m')  # Regex pour les séquences ANSI
        return len(ansi_escape.sub('', text))