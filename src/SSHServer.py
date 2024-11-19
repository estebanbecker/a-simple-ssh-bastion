import paramiko
import threading
import base64
from binascii import hexlify

class SSHServer(paramiko.ServerInterface):

    user = {}

    def __init__(self,logger,user):
        """
        Constructeur de la classe SSHServer
        logger: Objet logger pour journaliser les événements
        user: Dictionnaire contenant les informations des utilisateurs
        """

        self.event = threading.Event()
        self.logger = logger
        self.user = user

        host_key = paramiko.RSAKey(filename="test_rsa.key")
        self.logger.info("Read key: %s", hexlify(host_key.get_fingerprint()))

    def set_user(self, user):
        """
        Mettre à jour le dictionnaire des utilisateurs
        user: Dictionnaire contenant les informations des utilisateurs
        """
        self.user = user

    def check_channel_request(self, kind, chanid):
        """
        Vérifier si le canal demandé est autorisé
        kind: Type de canal demandé
        chanid: Identifiant du canal"""
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        """
        Vérifier l'authentification par mot de passe
        username: Nom d'utilisateur
        password: Mot de passe"""

        if username in self.user and password == self.user[username]['password']:
            self.logger.info(f"Authentification par mot de passe réussie pour {username}")
            print(f"Authentification par mot de passe réussie pour {username}")
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED
    
    def check_auth_publickey(self, username, key):
        """
        Vérifier l'authentification par clé publique
        username: Nom d'utilisateur
        key: Clé publique"""

        key_location = './user_keys/'
        try:
            # Vérifier si l'utilisateur existe
            if username not in self.user:
                return paramiko.AUTH_FAILED
            
            # Construire le chemin du fichier de la clé publique
            public_key_file = key_location + self.user[username]['public_key_file']
            
            # Récupérer la clé publique de l'utilisateur
            stored_key = self.get_public_key(public_key_file)
            if stored_key is None:
                return paramiko.AUTH_FAILED
            
            # Comparer les empreintes digitales des clés
            if key.get_fingerprint() == stored_key.get_fingerprint():
                self.logger.info(f"Clé publique vérifiée pour {username}")
                print(f"Clé publique vérifiée pour {username}")
                return paramiko.AUTH_SUCCESSFUL
        except Exception as e:
            self.logger.error(f"Erreur lors de la vérification de la clé publique pour {username}: {e}") 
            print(f"Erreur lors de la vérification de la clé publique pour {username}: {e}")
        
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_with_mic(
        self, username, gss_authenticated=paramiko.AUTH_FAILED, cc_file=None
    ):
        """
        Vérifier l'authentification GSSAPI
        username: Nom d'utilisateur
        gss_authenticated: Statut de l'authentification GSSAPI
        cc_file: Fichier de cache de l'authentification GSSAPI"""

        if gss_authenticated == paramiko.AUTH_SUCCESSFUL:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_keyex(
        self, username, gss_authenticated=paramiko.AUTH_FAILED, cc_file=None
    ):
        """
        Vérifier l'authentification GSSAPI avec échange de clés
        username: Nom d'utilisateur
        gss_authenticated: Statut de l'authentification GSSAPI
        cc_file: Fichier de cache de l'authentification GSSAPI"""

        if gss_authenticated == paramiko.AUTH_SUCCESSFUL:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def enable_auth_gssapi(self):
        """
        Activer l'authentification GSSAPI
        """
        return True

    def get_allowed_auths(self, username):
        """
        Récupérer les méthodes d'authentification autorisées"""
        return "gssapi-keyex,gssapi-with-mic,password,publickey"

    def check_channel_shell_request(self, channel):
        """
        Vérifier la demande de shell
        channel: Canal de communication"""

        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        """
        Vérifier la demande de terminal pseudo-TTY
        channel: Canal de communication
        term: Terminal
        width: Largeur
        height: Hauteur
        pixelwidth: Largeur en pixels
        pixelheight: Hauteur en pixels
        modes: Modes du terminal"""

        return True
    
    # Récupérer la clé publique de l'utilisateur
    def get_public_key(self,public_key_file):
        """
        Récupérer la clé publique de l'utilisateur
        public_key_file: Chemin du fichier de la clé publique
        """

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
            self.logger.error(f"Erreur lors de la lecture de la clé publique: {e}")
            print(f"Erreur lors de la lecture de la clé publique: {e}")
            return None
