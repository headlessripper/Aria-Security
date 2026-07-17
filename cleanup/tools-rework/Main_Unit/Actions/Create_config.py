# Create_config.py
import json
import os

def create_config():
    config_path = 'Main_Unit/Config.json'
    if os.path.exists(config_path):
        print("Config.json already exists!")
        return
    
    default_config = {
        "suspect_file_path": ""
    }
    with open(config_path, 'w') as f:
        json.dump(default_config, f, indent=2)
    print("Created Config.json with default structure.")

# Usage: create_config()
