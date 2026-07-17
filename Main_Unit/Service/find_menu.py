import os

def find_menu(icon_name):
    """Attempts to find the icon in and out of the script\'s directory.""" 
    script_dir = os.path.dirname(os.path.realpath(__file__))
    possible_paths = [os.path.join(script_dir, icon_name), os.path.join(script_dir, 'menu', icon_name), os.path.abspath(os.path.join(script_dir, os.pardir, icon_name))]
    for path in possible_paths:
        if os.path.exists(path):
            return path
    else:
        return None