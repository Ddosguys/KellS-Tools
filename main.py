import os

import sys

import time

import subprocess

from theme import set_theme, get_current_theme, themes

from pystyle import Colors, Colorate, Write



def animated_text(text, delay=0.05):

    for line in text.split('\n'):

        for char in line:

            sys.stdout.write(char)

            sys.stdout.flush()

            time.sleep(delay)

        sys.stdout.write('\n')

        sys.stdout.flush()

        time.sleep(delay)



def display_ascii_art():

    current_theme = get_current_theme()

    art = f"""{current_theme["primary"]}
    ██ ▄█▀▓█████  ██▓     ██▓      ██████          ▄▄▄█████▓ ▒█████   ▒█████   ██▓    
 ██▄█▒ ▓█   ▀ ▓██▒    ▓██▒    ▒██    ▒          ▓  ██▒ ▓▒▒██▒  ██▒▒██▒  ██▒▓██▒    
▓███▄░ ▒███   ▒██░    ▒██░    ░ ▓██▄            ▒ ▓██░ ▒░▒██░  ██▒▒██░  ██▒▒██░    
▓██ █▄ ▒▓█  ▄ ▒██░    ▒██░      ▒   ██▒         ░ ▓██▓ ░ ▒██   ██░▒██   ██░▒██░    
▒██▒ █▄░▒████▒░██████▒░██████▒▒██████▒▒           ▒██▒ ░ ░ ████▓▒░░ ████▓▒░░██████▒
▒ ▒▒ ▓▒░░ ▒░ ░░ ▒░▓  ░░ ▒░▓  ░▒ ▒▓▒ ▒ ░           ▒ ░░   ░ ▒░▒░▒░ ░ ▒░▒░▒░ ░ ▒░▓  ░
░ ░▒ ▒░ ░ ░  ░░ ░ ▒  ░░ ░ ▒  ░░ ░▒  ░ ░             ░      ░ ▒ ▒░   ░ ▒ ▒░ ░ ░ ▒  ░
░ ░░ ░    ░     ░ ░     ░ ░   ░  ░  ░             ░      ░ ░ ░ ▒  ░ ░ ░ ▒    ░ ░   
░  ░      ░  ░    ░  ░    ░  ░      ░                        ░ ░      ░ ░      ░  ░
 
 Developers : KellS
 ───────────────────── 
 
[1]-> Sql Vulenerability
[2]-> Web Scanner
[3]-> Brute Wifi 
[4]-> Phishing Attack
[5]-> DDoS IP
[6]-> Ip Tracer
[7]-> Email-Osint
[8]-> Osint Phone Number
[9]-> Username Osint
[10]-> Ip Generator

{current_theme["reset"]}"""

    animated_text(art, delay=0.00)
def execute_script(script_name):
    script_path = os.path.join('utils', f'{script_name}')
    try:
        subprocess.run(['python', script_path], check=True)
    except subprocess.CalledProcessError as e:
        print(f"{get_current_theme()['primary']}Error executing script '{script_name}': {e}{get_current_theme()['reset']}")

def main():
    install_packages(REQUIRED_PACKAGES)
    os.system('cls' if os.name == 'nt' else 'clear')

    current_theme = get_current_theme()

    warning_message = f"""
{current_theme["primary"]}
      ____               
     /___/\_     WARNING: The use of these tools can have significant
    _\   \/_/\__  risks and consequences. By using this software, you
  __\       \/_/\  agree that we are not responsible for any damage or
  \   __    __ \ \  issues that may arise from the use of these tools.
 __\  \_\   \_\ \ \   __ Please use responsibly and at your own risk.
/_/\\   __   __  \ \_/_/\          
\_\/_\__\/\__\/\__\/_\_\/             
   \_\/_/\       /_\_\/
      \_\/       \_\/
{current_theme["reset"]}
    """

    animated_text(warning_message, delay=0.01)

    input("\nPress Enter to continue...")

    os.system('cls' if os.name == 'nt' else 'clear')

    display_ascii_art()

    username = os.getlogin()
    while True:
        current_theme = get_current_theme()
        prompt = f"""
{current_theme["primary"]}╭─── {current_theme["secondary"]}KellS@user/tools{current_theme["reset"]}
{current_theme["primary"]}│
{current_theme["primary"]}╰─$ {current_theme["reset"]} """
        
        choice = input(prompt).strip()
        if choice == '1':

            execute_script('SQL Vulnerabitility.py')

        elif choice == '2':

            execute_script('Web Scanner.py')

        elif choice == '3':

            execute_script('Brute Wifi.py')

        elif choice == '4':

            execute_script('Phishing Attack.py')

        elif choice == '5':

            execute_script('DDoS IP.py')

        elif choice == '6':

            execute_script('IP TRACER.py')

        elif choice == '7':

            execute_script('Email-osint.py')

        elif choice == '8':

            execute_script('PHONE NUMBER OSINT.py')

        elif choice == '9':

            execute_script('Username Osint.py')

        elif choice == '10':

            execute_script('IP generator.py')
            print("\nAvailable themes:")

            for i, theme_name in enumerate(themes.keys(), 1):

                print(f"{i}. {theme_name}")

            theme_choice = input("Choose a theme by number: ").strip()

            theme_names = list(themes.keys())

            try:

                theme_index = int(theme_choice) - 1

                if 0 <= theme_index < len(theme_names):

                    set_theme(theme_names[theme_index])

                    os.system('cls' if os.name == 'nt' else 'clear')

                    display_ascii_art() 

                else:

                    print(f"{get_current_theme()['primary']}Invalid choice. No theme changed.{get_current_theme()['reset']}")

            except ValueError:

                print(f"{get_current_theme()['primary']}Invalid input. Please enter a number.{get_current_theme()['reset']}")



if __name__ == "__main__":

    main()
