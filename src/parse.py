import json

def parse_config(config_file):
    with open(config_file, 'r') as f:
        data = json.load(f)
    return data
        

if __name__ == '__main__':
    config_file = './src/config.json'
    config = parse_config(config_file)
    print(config)
