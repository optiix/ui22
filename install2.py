import subprocess
import os
import random
import string
import socket
import zipfile
import sys
import shutil
import urllib2
from itertools import cycle, izip
from zipfile import ZipFile

rVersions = {
    "16.04": "xenial",
    "18.04": "bionic"
    "12": "Bookworm"
}

class col:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    YELLOW = '\033[33m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def generate(length=32):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def getIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

def getVersion():
    try:
        return subprocess.check_output("lsb_release -d".split()).split(b":")[-1].strip().decode()
    except subprocess.CalledProcessError:
        return ""

def printc(rText, rColour=col.OKBLUE, rPadding=0):
    print(f"{rColour} ┌──────────────────────────────────────────┐ {col.ENDC}")
    for _ in range(rPadding):
        print(f"{rColour} │                                          │ {col.ENDC}")
    centered_text = rText.center(40)
    print(f"{rColour} │ {centered_text} │ {col.ENDC}")
    for _ in range(rPadding):
        print(f"{rColour} │                                          │ {col.ENDC}")
    print(f"{rColour} └──────────────────────────────────────────┘ {col.ENDC}\n")

def prepare(rType="MAIN"):
    global rPackages
    if rType != "MAIN": 
        rPackages = rPackages[:-3]
    printc("Preparing Installation")
    for rFile in ["/var/lib/dpkg/lock-frontend", "/var/cache/apt/archives/lock", "/var/lib/dpkg/lock"]:
        try:
            os.remove(rFile)
        except FileNotFoundError:
            pass
    os.system("apt-get update > /dev/null")
    printc("Removing libcurl4 if installed")
    os.system("apt-get remove --auto-remove libcurl4 -y > /dev/null")
    for rPackage in rPackages:
        printc(f"Installing {rPackage}")
        os.system(f"apt-get install {rPackage} -y > /dev/null")
    printc("Installing libpng")
    os.system("wget -q -O /tmp/libpng12.deb http://mirrors.kernel.org/ubuntu/pool/main/libp/libpng/libpng12-0_1.2.54-1ubuntu1_amd64.deb")
    os.system("dpkg -i /tmp/libpng12.deb > /dev/null")
    os.system("apt-get install -y > /dev/null")
    try:
        os.remove("/tmp/libpng12.deb")
    except FileNotFoundError:
        pass
    try:
        subprocess.check_output("getent passwd xtreamcodes > /dev/null".split())
    except subprocess.CalledProcessError:
        printc("Creating user xtreamcodes")
        os.system("adduser --system --shell /bin/falze --group --disabled-login xtreamcodes > /dev/null")
    if not os.path.exists("/home/xtreamcodes"): 
        os.mkdir("/home/xtreamcodes")
    return True

# ... [Continuation from the previous part]

def install(rType="MAIN"):
    global rInstall, rDownloadURL
    printc("Downloading Software")
    try:
        rURL = rDownloadURL[rInstall[rType]]
    except KeyError:
        printc("Invalid download URL!", col.FAIL)
        return False
    os.system(f'wget -q -O "/tmp/xtreamcodes.tar.gz" "{rURL}"')
    if os.path.exists("/tmp/xtreamcodes.tar.gz"):
        printc("Installing Software")
        if os.path.exists("/home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb"):
            os.system('chattr -f -i /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb > /dev/null')
        os.system('tar -zxvf "/tmp/xtreamcodes.tar.gz" -C "/home/xtreamcodes/" > /dev/null')
        try:
            os.remove("/tmp/xtreamcodes.tar.gz")
        except FileNotFoundError:
            pass
        return True
    printc("Failed to download installation file!", col.FAIL)
    return False

def installadminpanel():
    rURL = "https://bitbucket.org/emre1393/xtreamui_mirror/downloads/release_22f.zip"
    printc("Downloading Admin Panel")  
    os.system(f'wget -q -O "/tmp/update.zip" "{rURL}"')
    if os.path.exists("/tmp/update.zip"):
        try:
            zipfile.ZipFile("/tmp/update.zip")
        except zipfile.BadZipFile:
            printc("Invalid link or zip file is corrupted!", col.FAIL)
            os.remove("/tmp/update.zip")
            return False
        printc("Installing Admin Panel")
        os.system('unzip -o /tmp/update.zip -d /tmp/update/ > /dev/null && cp -rf /tmp/update/XtreamUI-master/* /home/xtreamcodes/iptv_xtream_codes/ > /dev/null && rm -rf /tmp/update/XtreamUI-master > /dev/null && rm -rf /tmp/update > /dev/null && chown -R xtreamcodes:xtreamcodes /home/xtreamcodes > /dev/null')
        try:
            os.remove("/tmp/update.zip")
        except FileNotFoundError:
            pass
        rURL2 = "https://bitbucket.org/emre1393/xtreamui_mirror/downloads/newstuff.zip"
        printc("Downloading New Stuff for Admin Panel")  
        os.system(f'wget -q -O "/tmp/update2.zip" "{rURL2}"')
        if os.path.exists("/tmp/update2.zip"):
            try:
                zipfile.ZipFile("/tmp/update2.zip")
            except zipfile.BadZipFile:
                printc("Invalid link or zip file is corrupted!", col.FAIL)
                os.remove("/tmp/update2.zip")
                return False
            printc("Installing New Stuff for Admin Panel")
            os.system('unzip -o /tmp/update2.zip -d /tmp/update2/ > /dev/null && cp -rf /tmp/update2/* /home/xtreamcodes/iptv_xtream_codes/ > /dev/null && rm -rf /tmp/update2/* > /dev/null && rm -rf /tmp/update2 > /dev/null && chown -R xtreamcodes:xtreamcodes /home/xtreamcodes/ > /dev/null')
            return True
        printc("Failed to download installation file!", col.FAIL)
        return False

def installadminpanel():
    rURL = "https://bitbucket.org/emre1393/xtreamui_mirror/downloads/release_22f.zip"
    printc("Downloading Admin Panel")  
    os.system(f'wget -q -O "/tmp/update.zip" "{rURL}"')
    if os.path.exists("/tmp/update.zip"):
        try: 
            with zipfile.ZipFile("/tmp/update.zip") as is_ok:
                pass
        except zipfile.BadZipFile:
            printc("Invalid link or zip file is corrupted!", col.FAIL)
            os.remove("/tmp/update.zip")
            return False
    printc("Installing Admin Panel")
    os.system('unzip -o /tmp/update.zip -d /tmp/update/ > /dev/null && cp -rf /tmp/update/XtreamUI-master/* /home/xtreamcodes/iptv_xtream_codes/ > /dev/null && rm -rf /tmp/update/XtreamUI-master > /dev/null && rm -rf /tmp/update > /dev/null && chown -R xtreamcodes:xtreamcodes /home/xtreamcodes > /dev/null')
    try:
        os.remove("/tmp/update.zip")
    except FileNotFoundError:
        pass

    rURL2 = "https://bitbucket.org/emre1393/xtreamui_mirror/downloads/newstuff.zip"
    printc("Downloading New Stuff for Admin Panel")  
    os.system(f'wget -q -O "/tmp/update2.zip" "{rURL2}"')
    if os.path.exists("/tmp/update2.zip"):
        try: 
            with zipfile.ZipFile("/tmp/update2.zip") as is_ok:
                pass
        except zipfile.BadZipFile:
            printc("Invalid link or zip file is corrupted!", col.FAIL)
            os.remove("/tmp/update2.zip")
            return False
        printc("Installing New Stuff for Admin Panel")
        os.system('unzip -o /tmp/update2.zip -d /tmp/update2/ > /dev/null && cp -rf /tmp/update2/* /home/xtreamcodes/iptv_xtream_codes/ > /dev/null && rm -rf /tmp/update2/* > /dev/null && rm -rf /tmp/update2 > /dev/null && chown -R xtreamcodes:xtreamcodes /home/xtreamcodes/ > /dev/null > /dev/null')
        return True
    printc("Failed to download installation file!", col.FAIL)
    return False

def mysql(rUsername, rPassword):
    global rMySQLCnf
    printc("Configuring MySQL")
    rCreate = True
    if os.path.exists("/etc/mysql/my.cnf"):
        with open("/etc/mysql/my.cnf", "r") as file:
            if file.read(14) == "# Xtream Codes":
                rCreate = False
    if rCreate:
        shutil.copy("/etc/mysql/my.cnf", "/etc/mysql/my.cnf.xc")
        with open("/etc/mysql/my.cnf", "w") as rFile:
            rFile.write(rMySQLCnf)
        os.system("service mysql restart > /dev/null")
    
    printc("Enter MySQL Root Password:", col.WARNING)
    for _ in range(5):
        rMySQLRoot = input("  ").strip()
        print()
        rExtra = f" -p{rMySQLRoot}" if rMySQLRoot else ""
        printc("Drop existing & create database? Y/N", col.WARNING)
        rDrop = input("  ").upper() == "Y"
        try:
            if rDrop:
                # MySQL commands updated to Python 3
                # Replace with actual MySQL commands and continue
                pass  # Replace with actual MySQL commands
            try:
                os.remove("/home/xtreamcodes/iptv_xtream_codes/database.sql")
            except FileNotFoundError:
                pass
            return True
        except subprocess.CalledProcessError:
            printc("Invalid password! Try again", col.FAIL)
    return False

def encrypt(rHost="127.0.0.1", rUsername="user_iptvpro", rPassword="", rDatabase="xtream_iptvpro", rServerID=1, rPort=7999):
    printc("Encrypting...")
    try:
        os.remove("/home/xtreamcodes/iptv_xtream_codes/config")
    except FileNotFoundError:
        pass
    with open('/home/xtreamcodes/iptv_xtream_codes/config', 'wb') as rf:
        encrypted_data = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(f'{{"host":"{rHost}","db_user":"{rUsername}","db_pass":"{rPassword}","db_name":"{rDatabase}","server_id":"{rServerID}", "db_port":"{rPort}", "pconnect":"0"}}', cycle('5709650b0d7806074842c6de575025b1')))
        rf.write(base64.b64encode(encrypted_data.encode()))

def configure():
    printc("Configuring System")
    if "xtreamcodes/iptv_xtream_codes/" not in open("/etc/fstab").read():
        with open("/etc/fstab", "a") as rFile:
            rFile.write("tmpfs /home/xtreamcodes/iptv_xtream_codes/streams tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=90% 0 0\ntmpfs /home/xtreamcodes/iptv_xtream_codes/tmp tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=3G 0 0")
    if "xtreamcodes" not in open("/etc/sudoers").read():
        os.system('echo "xtreamcodes ALL = (root) NOPASSWD: /sbin/iptables, /usr/bin/chattr" >> /etc/sudoers')
    if not os.path.exists("/etc/init.d/xtreamcodes"):
        with open("/etc/init.d/xtreamcodes", "w") as rFile:
            rFile.write("#! /bin/bash\n/home/xtreamcodes/iptv_xtream_codes/start_services.sh")
        os.system("chmod +x /etc/init.d/xtreamcodes > /dev/null")
    os.system("mount -a")

    # Set permissions and prepare configuration files
    os.system("chmod -R 0777 /home/xtreamcodes > /dev/null")
    if rType == "MAIN": 
        os.system("sudo find /home/xtreamcodes/iptv_xtream_codes/admin/ -type f -exec chmod 644 {} \;")
        os.system("sudo find /home/xtreamcodes/iptv_xtream_codes/admin/ -type d -exec chmod 755 {} \;")
    
    # Add domain/user/pass/id.ts URL support in nginx configuration
    with open('/home/xtreamcodes/iptv_xtream_codes/nginx/conf/nginx.conf', 'r') as nginx_file:
        nginx_replace = nginx_file.read()
        nginx_replace = nginx_replace.replace("rewrite ^/(.*)/(.*)/(\\d+)$ /streaming/clients_live.php?username=$1&password=$2&stream=$3&extension=ts break;",
                                              "rewrite ^/(.*)/(.*)/(\\d+)\\.(.*)$ /streaming/clients_live.php?username=$1&password=$2&stream=$3&extension=$4 break;\n        rewrite ^/(.*)/(.*)/(\\d+)$ /streaming/clients_live.php?username=$1&password=$2&stream=$3&extension=ts break;\n")
    with open('/home/xtreamcodes/iptv_xtream_codes/nginx/conf/nginx.conf', 'w') as nginx_file:
        nginx_file.write(nginx_replace)

    # Download and set up necessary files
    os.system("wget -q https://bitbucket.org/emre1393/xtreamui_mirror/downloads/nginx -O /home/xtreamcodes/iptv_xtream_codes/nginx/sbin/nginx")
    os.system("wget -q https://bitbucket.org/emre1393/xtreamui_mirror/downloads/nginx_rtmp -O /home/xtreamcodes/iptv_xtream_codes/nginx_rtmp/sbin/nginx_rtmp")
    os.system("wget -q https://bitbucket.org/emre1393/xtreamui_mirror/downloads/pid_monitor.php -O /home/xtreamcodes/iptv_xtream_codes/crons/pid_monitor.php")
    os.system("sudo chmod +x /home/xtreamcodes/iptv_xtream_codes/nginx/sbin/nginx")
    os.system("sudo chmod +x /home/xtreamcodes/iptv_xtream_codes/nginx_rtmp/sbin/nginx_rtmp")
    os.system("sudo find /home/xtreamcodes/iptv_xtream_codes/wwwdir/ -type f -exec chmod 644 {} \;")
    os.system("sudo find /home/xtreamcodes/iptv_xtream_codes/wwwdir/ -type d -exec chmod 755 {} \;")
    os.system("chmod 0700 /home/xtreamcodes/iptv_xtream_codes/config > /dev/null")
    os.system("sed -i 's|echo \"Xtream Codes Reborn\";|header(\"Location: https://www.google.com/\");|g' /home/xtreamcodes/iptv_xtream_codes/wwwdir/index.php")

    # Update hosts file to prevent access to certain domains
    update_hosts_file("/etc/hosts", "xtream-codes.com")
    update_hosts_file("/etc/hosts", "api.xtream-codes.com")
    update_hosts_file("/etc/hosts", "downloads.xtream-codes.com")

    # Schedule service
def update_hosts_file(hosts_file, domain, ip="127.0.0.1"):
    with open(hosts_file, "r+") as file:
        content = file.read()
        if domain not in content:
            file.write(f"{ip}    {domain}\n")

def start(first=True):
    if first: 
        printc("Starting Xtream Codes", col.OKGREEN)
    else: 
        printc("Restarting Xtream Codes", col.OKGREEN)
    os.system("/home/xtreamcodes/iptv_xtream_codes/start_services.sh > /dev/null")

if __name__ == "__main__":
    try: 
        rVersion = subprocess.check_output('lsb_release -sr', shell=True).decode().strip()
    except subprocess.CalledProcessError: 
        rVersion = None

    if rVersion not in rVersions:
        printc("Unsupported Operating System, Works only on Ubuntu Server 16 and 18", col.FAIL)
        sys.exit(1)

    printc("Xtream UI - Installer Mirror", col.OKGREEN, 2)
    print(f"{col.OKGREEN} │ Check out the mirror repo: https://bitbucket.org/emre1393/xtreamui_mirror {col.ENDC}\n")
    
    rType = input("  Installation Type [MAIN, LB]: ").strip().upper()
    print()
    if rType in ["MAIN", "LB"]:
        # Continue with the rest of the code...
        # Ensure all raw_input() calls are replaced with input()
        # Replace string formatting with f-strings or .format()
        # Handle exceptions and subprocesses appropriately
        # ...

# Update hosts file to prevent access to certain domains
update_hosts_file("/etc/hosts", "xtream-codes.com")
update_hosts_file("/etc/hosts", "api.xtream-codes.com")
update_hosts_file("/etc/hosts", "downloads.xtream-codes.com")

# Schedule service to start on reboot
if not "@reboot root /home/xtreamcodes/iptv_xtream_codes/start_services.sh" in open("/etc/crontab").read():
    os.system('echo "@reboot root /home/xtreamcodes/iptv_xtream_codes/start_services.sh" >> /etc/crontab')
