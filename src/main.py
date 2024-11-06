import os
import paramiko
import socket
import threading
import logging
import time

logging.basicConfig(level=logging.DEBUG)
paramiko.util.log_to_file("paramiko_debug.log")

# Configuration
LOCAL_HOST = '0.0.0.0'
LOCAL_PORT = 42345
REMOTE_HOST = 'IP'
REMOTE_PORT = 22
REMOTE_USER = 'user'
REMOTE_PASSWORD = 'password'

# Path to the RSA key file
RSA_KEY_PATH = 'test_rsa.key'

# Check if the RSA key file exists
if not os.path.isfile(RSA_KEY_PATH):
    raise FileNotFoundError(f"RSA key file '{RSA_KEY_PATH}' not found.")

class SSHProxy(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # Authentification locale (à adapter selon vos besoins)
        if username == 'local_user' and password == 'local_password':
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

def handle_client(client_socket):
    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(paramiko.RSAKey(filename=RSA_KEY_PATH))
        server = SSHProxy()
        transport.start_server(server=server)

        print("Waiting for channel request...")
#        channel = transport.open_channel(kind='session')
        channel = transport.accept(20)
        if channel is None:
            print("No channel.")
            return

        print("Channel accepted.")

        # Check if the channel is open
        if not channel.active:
            print("Channel is not active.")
            return

        print("Channel is active.")

        remote_transport = paramiko.Transport((REMOTE_HOST, REMOTE_PORT))
        remote_transport.connect(username=REMOTE_USER, password=REMOTE_PASSWORD)
        remote_channel = remote_transport.open_session()

        def forward_data(src, dst):
            try:
                while True:
                    data = src.recv(1024)
                    if not data:
                        break
                    dst.send(data)
            except Exception as e:
                print(f"Error: {e}")
            finally:
                src.close()
                dst.close()

        threading.Thread(target=forward_data, args=(channel, remote_channel)).start()
        threading.Thread(target=forward_data, args=(remote_channel, channel)).start()

        # Handle PTY and shell requests
        try:
            channel.get_pty()
            channel.invoke_shell()
            print("PTY allocated and shell invoked.")
        except paramiko.SSHException as e:
            print(f"SSHException: {e}")

    except Exception as e:
        print(f"Exception in handle_client: {e}")
    finally:
        client_socket.close()

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((LOCAL_HOST, LOCAL_PORT))
    server_socket.listen(10)
    print(f"Listening on {LOCAL_HOST}:{LOCAL_PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == '__main__':
    main()