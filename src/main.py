from bastion import Bastion

def start_bastion(host, port):
    bastion = Bastion(host, port)
    bastion.start()


if __name__ == "__main__":
    start_bastion('0.0.0.0', 2222)