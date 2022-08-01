#!/usr/bin/python3
 
from colorama import Fore, Back, Style
from shutil import which
from phonenumbers import geocoder
import shutil
import phonenumbers
from shodan import Shodan
from googlesearch import search
from urllib.request import urlopen
from fake_useragent import UserAgent
from urllib.parse import urljoin
from builtwith import builtwith
from pygeocoder import Geocoder
from os import path, system
import time
import os.path
import socket, time, os, dns.resolver, sys, urllib, urllib.request, subprocess
import shodan
import requests, io, sys
import ipaddress
import whois
import http.client
import ftplib
import ssl
import re
import json
import uuid
 
#####################################################################
#                                                                   #
# IGF - Information Gathering Framework v1.9 by c0deninja           #
#                                                                   #
# pip3 install -r requirements.txt                                  #
#                                                                   #
#####################################################################
 
banner = """

                                    
 ██▓     ▄████      █████▒        
 ▓██▒    ██▒ ▀█▒   ▓██   ▒       
 ▒██▒   ▒██░▄▄▄░   ▒████ ░       
 ░██░   ░▓█  ██▓   ░▓█▒  ░
 ░██░   ░▒▓███▀▒   ░▒█░    
 ░▓      ░▒   ▒     ▒ ░    
 ▒ ░     ░   ░     ░      
 ▒ ░   ░ ░   ░     ░ ░   v1.10
 ░           ░                                        

"""
class Infogath:
 
    def commands(self, cmd):
        try:
            subprocess.check_call(cmd, shell=True)
        except:
            pass

    def Updates(self):
        directory = os.path.abspath(os.getcwd())
        self.commands(f"sudo apt install amass sublist3r subfinder ffuf gobuster enum4linux patator hydra")       
        self.commands(f"sudo pip install dnspython ipaddress fake-useragent python-whois colorama shodan builtwith phonenumbers googlesearch-python pygeocoder jq")
        self.commands(f"cd {directory}/CMSeeK | git pull")
        self.commands(f"cd {directory}/CMSmap | git pull")
        self.commands(f"cd {directory}/XSStrike | git pull")
        self.commands(f"cd {directory}/torghost | git pull")


    def config(self):
        config = {}
        domain = input("Domain: ")
        config['domain'] = []
        config['domain'].append({'site': domain})
        with open("config.txt", "w") as f:
            json.dump(config, f)  
        self.start()

    def siteconfig(self):
        with open('config.txt') as json_file:
            data = json.load(json_file)
            for conf in data['domain']:
                return conf['site']

    def displayconfig(self):
          with open('config.txt') as json_file:
            data = json.load(json_file)
            for conf in data['domain']:
                print(Fore.RED + "[" + Fore.CYAN + conf['site'] + Fore.RED + "]")
    
    def DetectFirewall(self):
        if path.exists("firewallplayground/WhatWaf"):
            print("Found WhatWaf!")
            currentpath = os.path.abspath(os.getcwd())
            self.commands(f"{currentpath}/firewallplayground/WhatWaf/whatwaf --url {self.siteconfig()} --skip ")
        if not path.exists("firewallplayground/WhatWaf"):
            print("No such directory")

    def NmapScan(self):
        if which("nmap"):
            ip = self.siteconfig()
            self.commands(f"sudo nmap -sV -sC -v -p- --min-rate 5000 -T4 {ip} -Pn")
        else:
            self.enumeration()
    
    def patatorSSH(self):
        if which("patator"):
            user = input("User: ")
            wordlist = input("Wordlist: ")
            self.commands(f"patator ssh_login host={self.siteconfig()} user='{user} password=FILE0 0={wordlist} -x ignore:mesg='Authentication failed'")
        else:
            self.Patator()

    def patatorFTP(self):
        if which("patator"):
            user = input("User: ")
            wordlist = input("Password: ")
            self.commands(f"patator ftp_login host={self.siteconfig()}  user={user} password=FILE0 0={wordlist} -x ignore:mesg='Login incorrect.' -x ignore,reset,retry:code=500'")
        else:
            self.Patator()

    def CMERid(self):
        user = input("User: ")
        password = input("Password: ")
        self.commands(f"cme smb {self.siteconfig()} -u {user} -p {password} --rid-brute")

    def CMESPider(self):
        user = input("User: ")
        password = input("Password: ")
        share = input("Share: ")
        extension = input("Extension: ")
        self.commands(f"cme smb {self.siteconfig()} -u {user} -p {password} --spider {share} --pattern {extension}")

    def CMEUser(self):
        password = input("Password: ")
        wordlist = input("Wordlist: ")
        self.commands(f"cme smb {self.siteconfig()} -u {wordlist} -p {password}")

    def CMEPasswords(self):
        user = input("User: ")
        wordlist = input("Wordlist: ")
        self.commands(f"cme smb {self.siteconfig()} -u {user} -p {wordlist}")

    def SMBShares(self):
        user = input("User: ")
        password = input("Pass: ")
        self.commands(f"cme smb {self.siteconfig()} --shares -u {user} -p {password}")

    def WPScanPasswords(self):
        if which("wpscan"):
            print(f"{Fore.CYAN} Found WPScan!\n")
            wordlist = input("Wordlist: ")
            users = input("UserList: ")
            if wordlist == "": 
                self.commands(f"wpscan --url {self.siteconfig()} --passwords /usr/share/wordlists/rockyou.txt -U {users}")  
            else:
                self.commands(f"wpscan --url {self.siteconfig()} --passwords {wordlist} -U {users}") 

    def WPScanUserEnumeration(self):
        if which("wpscan"):
            print(f"{Fore.CYAN} Found WPscan!\n")
            self.commands(f"wpscan --url {self.siteconfig()} --enumerate u")
        else:
            print(f"{Fore.RED} WPScan not installed!")
            self.WPScan()

    def WPScanNormal(self):
        if which("wpscan"):
            print(f"{Fore.CYAN} Found WPscan!\n")
            self.commands(f"wpscan --url {self.siteconfig()}")
        else:
            print(f"{Fore.RED} WPScan not installed!")
            self.WPScan()


    def hydraFTP(self):
        ask = input("Will you be cracking usernames, passwords or both? (user/pass/both): ")
        ip = self.config
        if ask == "user":
            wordlist = input("Wordlist: ")
            self.commands(f"hydra -L {wordlist} -p test {ip} -t 50 ftp -V")
        elif ask == "pass":
            username = input("Username: ")
            wordlist = input("Wordlist: ")
            self.commands(f"hydra -l {username} -P {wordlist} {ip} -t 50 ftp -V")
        elif ask == "both":
            passwordlist = input("Pass Wordlist: ")
            usernamewordlist = input("Username Wordlist: ")
            self.commands(f"hydra -L {passwordlist} -P {usernamewordlist} {ip} -t 50 ftp -V")     

    def hydraSSH(self):
        ask = input("Will you be cracking usernames, passwords or both? (user/pass/both): ")
        ip = self.config
        if ask == "user":
            wordlist = input("Wordlist: ")
            self.commands(f"hydra -L {wordlist} -p test {ip} -t 50 ssh -V")
        elif ask == "pass":
            username = input("Username: ")
            wordlist = input("Wordlist: ")
            self.commands(f"hydra -l {username} -P {wordlist} {ip} -t 50 ssh -V")
        elif ask == "both":
            passwordlist = input("Pass Wordlist: ")
            usernamewordlist = input("Username Wordlist: ")
            self.commands(f"hydra -L {passwordlist} -P {usernamewordlist} {ip} -t 50 ssh -V")

    def hydraLOGIN(self):
        ask = input("Will you be cracking usernames, passwords or both?  (user/pass/both): ")
        ip = self.config
        login = input("Login Page: ")
        error = input("Login Error: ")      
        if ask == "user":
            wordlist = input("Wordlist: ")
            self.commands(f"hydra -L {wordlist} -p pass {self.config} http-post-form '{login}:username=^USER^&password=^PASS^:{error}.'")
        elif ask == "pass":
            user = input("User: ")
            wordlist = input("Wordlist: ")
            self.commands(f"hydra -l {user} -P {wordlist} {self.config} http-post-form '{login}:username=^USER^&password=^PASS^:{error}.'")
        elif ask == "both":
            user = input("User: ")
            password = input("Pass: ")
            self.commands(f"hydra -L {user} -P {password} {self.config} http-post-form '{login}:username=^USER^&password=^PASS^:{error}.'")


    def cmsmap(self):
        if path.exists("CMSmap"):
            cmspath = os.path.abspath(os.getcwd())
            self.commands(f"python3 {cmspath}/CMSmap/cmsmap.py {self.siteconfig()}")
        if not path.exists("CMSmap"):
            print("We couldn't find the CMSmap directory")
            self.DirectoryPlayground()
                
    def torghost(self):
        if which("torghost"):
            while True:
                print("\n")
                print (Fore.RED + "[" + Fore.CYAN + "1" + Fore.RED + "]" + Fore.WHITE + "  Start")  
                print (Fore.RED + "[" + Fore.CYAN + "2" + Fore.RED + "]" + Fore.WHITE + "  Stop") 
                print (Fore.RED + "[" + Fore.CYAN + "3" + Fore.RED + "]" + Fore.WHITE + "  Switch") 
                print (Fore.RED + "[" + Fore.CYAN + "4" + Fore.RED + "]" + Fore.WHITE + "  Exit")
                print("\n")
                
                prompt = input(Fore.CYAN + "TorGhost~" + Fore.RED + "# ")
                if prompt == "1":
                    self.commands("sudo torghost --start")
                if prompt == "2":
                    self.commands("sudo torghost --stop")
                if prompt == "3":
                    self.commands("sudo torghost --switch")
                if prompt == "4":
                    self.start()
        else:
            install = input("TorGhost is not installed, do you want to install it??? (y/n): ").lower()
            if install == "y":
                path_igf = os.getcwd()
                self.commands("git clone https://github.com/SusmithKrishnan/torghost.git")
                self.commands(f"cd {path_igf}/torghost")
                self.commands(f"chmod +x {path_igf}/torghost/build.sh")
                self.commands(f"bash {path_igf}/torghost/build.sh")
                if os.path.exists(f"torghost"):
                    print("torghost cloned successfully!")
                else:
                    print(Fore.RED + "torghost couldn't be cloned")
                if not which("toghost"):
                    print("torghost not installed")
                else:
                    pass
            else:
                self.start()


    def myip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local = socket.gethostname()
        print("\n")
        print(Fore.GREEN + f"Public: {s.getsockname()[0]}")
        print(Fore.GREEN + f"Local: {socket.gethostbyname(local)}")
        print ("MAC: " + ':'.join(re.findall('..', '%012x' % uuid.getnode()))) 


    def dirb(self):
        if which("dirb"):
            self.commands(f"dirb {self.siteconfig()}")
        else:
            install = input("Dirb is not installed, Do you want to install it??? (y/n): ").lower()
            if install == 'y':
                self.commands("sudo apt install dirb")
                if which("dirb"):
                    print(Fore.GREEN + "dirb installed successfully!!")
                else:
                    print(Fore.CYAN + "dirb wasn't installed")
                    self.DirectoryPlayground()
            if install == "n":
                self.DirectoryPlayground()

    def fuff(self):
        if which("ffuf"):
            self.commands(f"ffuf -w /usr/share/dirbuster/wordlists/directory-list-1.0.txt -u {self.siteconfig()}/FUZZ -e php,html,txt")
        else:
            ask = input("ffuf is not installed, do you want to install it (y/n): ").lower()
            if ask == "y":
                self.commands("sudo apt install ffuf")
                if which("ffuf"):
                    print(Fore.GREEN + "ffuf installed successfully!")
                    self.DirectoryPlayground()
                else:
                    print("ffuf is not installed")
                    self.DirectoryPlayground()
            if ask == "n":
                self.DirectoryPlayground()    

    def dirsearch(self):
        path = os.path.abspath(os.getcwd())
        self.commands(f"python3 {path}/directoryplayground/dirsearch/dirsearch.py -e php,html,txt -u {self.siteconfig}")
        print(self.siteconfig)
    
    def smbclient(self):
        if which("smbclient"):
            cli = input("SmbClient: ")
            self.commands(f"smbclient {cli}")
        else:
            print(Fore.CYAN + "smbclient not found")
            self.SmbPlayground()

    
    def subover(self):
        if which("SubOver"):
            domain = self.siteconfig()
            self.commands(f"SubOver -l {domain}")
        else:
            ask = input("SubOver is not installed, do you want to install it?? y/n: ")
            if ask == "y":
                home = os.environ['HOME']  
                self.commands("go get github.com/Ice3man543/SubOver | cd {}/go/bin | sudo mv {}/go/bin/SubOver /usr/local/bin".format(home, home))
            if ask == "n":
                self.SubdomainPlayground()


    def rapiddns(self):
        rapiddnspath = os.path.abspath(os.getcwd())
        domain = self.siteconfig()
        if "https://" in domain:
            domain = domain.replace("https://", "")
        if "http://" in domain:
            domain = domain.replace("http://", "")  
        if path.exists(f"{rapiddnspath}/subdomainplayground/rapiddns.sh"):
            self.commands(f"bash {rapiddnspath}/subdomainplayground/rapiddns.sh {domain}")
        if not path.exists(f"{rapiddnspath}/subdomainplayground/rapiddns.sh"):
            print(Fore.RED + "rapiddns.sh not found!")


    def httprobe(self):
        if which("httprobe"):
            domains = input("domains to check: ")
            self.commands(f"cat {domains} | httprobe | anew")
        else:
            ask = input("httrobe is not installed, do you want to install it?? y/n: ")
            if ask == "y":
                home = os.environ['HOME']  
                self.commands("go get -u github.com/tomnomnom/httprobe | cd {}/go/bin | sudo mv {}/go/bin/httprobe /usr/local/bin".format(home, home))
            if ask == "n":
                self.webinfo()

    
    def nikto(self):
        if which("nikto"):
            self.commands(f"nikto -h {self.siteconfig()}")
        else:
            install = input("Do you want to install nikto??? y/n: ").lower()
            if install == "y":
                self.commands("sudo apt install nikto")
                if which("nikto"):
                    print(Fore.GREEN +  "Nikto installed successfully!!")
                else:
                    print(Fore.RED + "Nikto didn't installed!")
            if install == "n":
                self.vulnerability()
    
    def cmseek(self):
        if path.exists("CMSeeK"):
            print("Found CMSeeK!")
            site = self.siteconfig()
            cmseekpath = os.path.abspath(os.getcwd())
            self.commands("python3 {}/CMSeeK/cmseek.py -u {} --random-agent".format(cmseekpath, site))
        if not path.exists("CMSeeK"):
            install = input("We couldn't find cmseek, do you want to install it?? y/n: ")
            if install == 'y':
                seekpath = os.path.abspath(os.getcwd())
                self.commands("git clone https://github.com/Tuhinshubhra/CMSeeK")
                self.commands("pip3 install -r {}/CMSeeK/requirements.txt".format(seekpath))
                if path.exists("CMSeeK"):
                    print("CMSeeK sucessfully cloned!")
                if not path.exists("CMSeeK"):
                    print("CMSeek not cloned!!")
                    self.webinfo()
            if install == 'n':
                self.webinfo()

    
    def nmapvuln(self):
        print("======== Vulnerability scan with Nmap ========\n")
        site = self.siteconfig()
        if "https://" or "http://" or "https://www." or "http://www." in site:
            print(f"{Fore.RED} please use site.com")
            self.vulnerability()
        self.commands("nmap --script vuln {}".format(site))
    
    def shellshock(self):
        print("======= Scanning for shellshock vulnerability =======\n")
        site = self.siteconfig()
        if "https://" or "http://" or "https://www." or "http://www." in site:
            print(f"{Fore.RED} please use site.com")
            self.vulnerability()
        self.commands("nmap -sV -p- --script http-shellshock {}".format(site))
    
    def heartbleedvuln(self):
        print("======= Scanning for the HeartBleed vulnerability =======\n")
        site = self.siteconfig()
        if "https://" or "http://" or "https://www." or "http://www." in site:
            print(f"{Fore.RED} please use site.com")
            self.vulnerability()
        self.commands("nmap -p 443 --script ssl-heartbleed {}".format(site))
    
    def drupageddon(self):
        print("====== Scanning for the Drupageddon vulnerability ======\n")
        site = self.siteconfig()
        if "https://" or "http://" or "https://www." or "http://www." in site:
            print(f"{Fore.RED} please use site.com")
            self.vulnerability()
        self.commands("nmap --script http-vuln-cve2014-3704 --script-args http-vuln-cve2014-3704.cmd='uname -a',http-vuln-cve2014-3704.uri='/drupal' {}".format(site))
    
    def drupageddon2(self):
        if path.exists("vulnerability/Drupageddon2.py"):
            print("Found the exploit!!")
            drupapath = os.path.abspath(os.getcwd())
            try:
                self.commands("python3 {}/vulnerability/Drupageddon2.py".format(drupapath))
            except:
                pass
        if not path.exists("vulnerability/Drupageddon2.py"):
            print("You're missing the exploit..")
            self.vulnerability()
    
    def apachestruts(self):
        if path.exists("vulnerability/apachestruts.py"):
            print("Found the exploit!!")
            apachestruts = os.path.abspath(os.getcwd())
            site = self.siteconfig()
            self.commands("python3 {}/vulnerability/apachestruts.py -u {}".format(apachestruts, site))
        if not path.exists("vulnerability/apachestruts.py"):
            print("You're missing the exploit..")
            self.vulnerability()
    
    def xsstrike(self):
        site = self.siteconfig()
        if path.exists("XSStrike"):
            print("Found XSStrike!")
        if not path.exists("XSStrike"):
            install = input("Couldnt find XSStrike, do you want to clone it??? Y/N").lower()
            if install == "y":
                self.commands("git clone https://github.com/s0md3v/XSStrike.git")
                if path.exists("XSStrike"):
                    print("sucessfully cloned XSStrike")
            if install == "n":
                self.vulnerability()
        xsstrikepath = os.path.abspath(os.getcwd())      
        self.commands("python3 {}/XSStrike/xsstrike.py -u {}".format(xsstrikepath, site))
        

    def knockpy(self):
        print("checking to see if knockpy is installed..\n")
        if which("knockpy"):
            site = self.siteconfig()
            self.commands("knockpy {}".format(site))
        else:
            install = input("knockpy isnt installed, you want to install it now?? y/n: ")
            if install == "y":
                self.commands("sudo apt install knockpy")
                if which("knockpy"):
                    print("knockpy successfully installed!!")

    
    def subfinder(self):
        print("Checking to see if subfinder is installed..\n")
        if which("subfinder"):
            site = self.siteconfig()
            if "https://" in site:
                site = site.replace("https://", "")
            if "http://" in site:
                site = site.replace("http://", "")  
            self.commands("subfinder -d {}".format(site))       
        else:    
            install = input("subfinder isn't installed, you want to install it now?? y/n: ")
            if install == 'y':
                self.commands("git clone https://github.com/projectdiscovery/subfinder.git")
                self.commands("cd subfinder/cmd/subfinder | go build .")
                self.commands("mv subfinder /usr/local/bin")
                if which("subfinder"):
                    print("Successfully installed subfinder")
            if install == "n":
                self.SubdomainPlayground()


    def sublister(self):
        print("Checking to see if sublist3r is installed")
        if which("sublist3r"):
            print (Fore.GREEN + "Sublist3r is already installed!!\n")
            site = self.siteconfig()
            if "https://" in site:
                site = site.replace("https://", "")
            if "http://" in site:
                site = site.replace("http://", "")
            print(site)
            cmd = "sublist3r -d {}".format(site)
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            out, err = p.communicate()
            out = out.decode()  
            print(out)        
            savefile = input("Do you want to save the output to file? y/n: ")
            if savefile == "y":
                with open("sublisterdomains.txt", "w") as sublister:
                    sublister.writelines(out)
                if path.exists("sublisterdomains.txt"):
                    print("file sucessfully saved!")
                if not path.exists("sublisterdomains.txt"):
                    print("Couldnt save file")
            if savefile == "n":
                self.SubdomainPlayground()
        else:            
            install = input("sublist3r isn't installed, you want to install it now?? y/n: ")
            if install == 'y':
                if which("pip3") == False:
                    print("You need pip3 to install sublist3r")
                    self.SubdomainPlayground()
                else:
                    self.commands('sudo pip3 install sublist3r')
                if which("sublist3r"):
                    print("sublist3r installed successfully!")
                else:
                    print("sublist3r wasn't installed")



    def amassdomain(self):
        print(Fore.CYAN + "Checking to see if amass is installed...\n")
        if which("amass"):
            print(Fore.GREEN + "amass is already installed!\n")
            domain = self.siteconfig()
            if "https://" in domain:
                domain = domain.replace("https://", "")
            if "http://" in domain:
                site = domain.replace("http://", "")            
            cmd = "amass enum -passive -d {}".format(domain)
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            out, err = p.communicate()
            out = out.decode()
            print(out)
            save = input("Do you want to save the ouput to a file?? y/n: ")
            if save == 'y':
                with open("amassoutput.txt", "w") as f:
                    f.writelines(out)
                if path.exists("amassoutput.txt"):
                    print(Fore.GREEN + "amassoutput.txt saved successfully!")
                if not path.exists("amassoutput.txt"):
                    print(Fore.RED + "Could not be saved to a file!")
            if save == 'n':
                pass
        else:
            install = input("amass isn't installed, you want to install it now?? y/n: ")
            if install == 'y':
                self.commands("sudo apt installl amass")
                if which("amass"):
                    print("Amass installed successfully")


    def spotter(self):
        print (Fore.CYAN + "bash code by nahamsec \n")
        site = self.siteconfig()
        if "https://" in site:
            site = site.replace("https://", "")
        if "http://" in site:
            site = site.replace("http://", "")          
        print(Fore.GREEN)
        cmd = "./subdomainplayground/spotter.sh {}".format(site)
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, err = p.communicate()
        out = out.decode()
        print(out)
        save = input("Save output to a file?? y/n: ").lower()
        if save == "y":
            name = input("Name of file to save: ")
            if name == "":
                self.SubdomainPlayground()
            with open(name, 'w') as f:
                f.writelines(out)
            if path.exists(f"{name}"):
                print(f"{name} successfully saved!")
            if not path.exists(f"{name}"):
                print(f"Couldn't save {name}")
        elif save == "n":
            self.SubdomainPlayground()


    def certsh(self):
        print (Fore.CYAN + "bash code by nahamsec \n")
        site = self.siteconfig()
        if "https://" in site:
            site = site.replace("https://", "")
        if "http://" in site:
            site = site.replace("http://", "")  
        print(Fore.GREEN)
        cmd = "./subdomainplayground/certsh.sh {}".format(site)
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, err = p.communicate()
        out = out.decode()
        print(out)
        save = input("Save output to a file?? y/n: ").lower()
        if save == "y":
            name = input("Name of file to save: ")
            if name == "":
                self.SubdomainPlayground()            
            with open(name, 'w') as f:
                f.writelines(out)
            if path.exists(f"{name}"):
                print(f"{name} successfully saved!")

            if not path.exists(f"{name}"):
                print(f"Couldn't save {name}")
        elif save == "n":
            self.SubdomainPlayground()


    def smbvulnscan(self):
        ip = self.siteconfig()
        port = input("SMB Port: ")
        self.commands(f"nmap -p{port} --script smb-vuln-* {ip} -Pn")
    
    def lookupsids(self):
        pathfile = os.path.abspath(os.getcwd())
        if path.exists(f"{pathfile}/smbplayground/lookupsid.py"):
            print (Fore.GREEN + "Found lookupsid.py!\n")
            print("\n")
            print(Fore.WHITE)
            user = input("Enter User: ")
            password = input("Enter Password: ")
            ip = self.siteconfig()
            print("\n")
            self.commands(Fore.LIGHTGREEN_EX + "sudo python lookupsid.py {}:{}@{}".format(user, password, ip))

        if not path.exists(f"{pathfile}/smbplayground/lookupsid.py"):
            directory = os.path.abspath(os.getcwd())
            print (Fore.RED + "Could not find lookupsid.py in {}".format(directory))
            self.SmbPlayground()

    
    def enumforlinux(self):
        print ("Checking to see if enum4linux is installed...\n")
        if which("enum4linux"):
            print (Fore.GREEN + "enum4linux is already installed!\n")
            ip = self.siteconfig()
            self.commands("enum4linux {}".format(ip))
        else:
            print ("enum4linux is not installed")
            ask = input("Do you want to install enum4linux? y/n: ").lower()
            if ask == "y":
                self.commands("sudo apt install enum4linux")
                print ("enum4linux installed!!")
            elif ask == "n":
                self.SmbPlayground()


    def evilwinrm(self):
        if path.exists('evil-winrm'):
            pass
        if not path.exists('evil-winrm'):
            print (Fore.RED + "No evil-winrm directory found!\n")
            install = input("Do you want to clone it from github? y/n: ").lower()
            if install == "y":
                os.system("git clone https://github.com/Hackplayers/evil-winrm.git")
                if path.exists('evil-winrm'):
                    print (Fore.GREEN + 'evil-winrm has been cloned!\n')
                if not path.exists("Could not find evil-winrm directory"):
                    self.WindowsHax()
            if install == "n":
                self.WindowsHax()
        print ("\n")
        print("============== Evil-WinRM ================\n")
        ip = self.siteconfig()
        user = input("Enter user: ")
        password = input("Enter password: ")
        rubyfile = os.path.abspath(os.getcwd())
        os.system("ruby {}/evil-winrm/evil-winrm.rb -i {} -u {} -p '{}'".format(rubyfile, ip, user, password))


    def windowsexploitation(self):
        if path.exists('Windows-Exploit-Suggester'):
            pass
        if not path.exists('Windows-Exploit-Suggester'):
            print (Fore.RED + "Windows Exploit Suggester is not here!\n")
            install = input("Do you want to clone it from github?? y/n: ").lower()
            if install == "y":
                os.system("git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git")
                if path.exists('Windows-Exploit-Suggester'):
                    print (Fore.GREEN + "Windows Exploit Suggester cloned!\n")
                    print (Fore.GREEN + "Updating the  database...\n")
                    self.commands("python windows-exploit-suggester.py --update")
                    print ("Done updating!\n")  
                if not path.exists("Couldn't find the Windows-Exploit-Suggester directory"):
                    self.WindowsHax()
            elif install == "n":
                self.WindowsHax()
        print ("============== Windows Exploit Suggester ==============\n")
        directory = 'Windows-Exploit-Suggester'
        dbsfile = os.listdir(directory)
        for files in dbsfile:
            if files.endswith(".xls"):
                files = files.strip()
                dbsfilepath = os.path.abspath(os.getcwd())
                systeminfo = dbsfilepath + "/" + directory + "/" + 'systeminfo.txt'
                files = dbsfilepath + "/" + directory + "/" + files
                print (Fore.GREEN + "Found: {}\n".format(files))
                cmd = os.system("python {}/Windows-Exploit-Suggester/windows-exploit-suggester.py -u --database {} --system {}".format(dbsfilepath, files, systeminfo))
                print (cmd)
                with open('exploits.txt', 'w') as f:
                    f.writelines(str(cmd))
 
    def ftpuserenum(self):
        if path.exists("ftp_user_enum.pl"):
            pass
        if not path.exists("ftp_user_enum.pl"):
            print (Fore.RED + "file ftp_user_enum.pl not found, exiting!")
            self.enumeration()
        ip = self.siteconfig()
        user = input("User to enumerate: ")
        print(Fore.GREEN + "\n")
        print("==================== FTP User Enumeration ===================" + "\n")
        self.commands("perl ftp_user_enum.pl -u {} -t {}".format(user, ip))
 
    def dnsenum(self):
        domain = self.siteconfig()
        if domain == "":
            print (Fore.RED + "Please dont leave this blank!")
            self.enumeration()
        print ("\n")
        print(Fore.GREEN)
        print("================= DNS Enumeration ==================" + "\n")
        self.commands("host -t ns " + domain + "\n")
        self.commands("host -t mx " + domain + "\n")
        self.commands("nslookup " + domain + "\n")
        self.commands("dig " + domain + "\n")
        self.commands("dig +nocmd " + domain + " ANY +noall +answer" + "\n")
 
 
    def phonenuminfo(self):
        phonenumber = input("Enter Phone number: ")
        countrycode = input("Enter Country (Ex: US): ")
        try:
            number = phonenumbers.parse(phonenumber, countrycode)
            print("\n")
            print("Checking to see if the number: {} is valid".format(phonenumber))
            print("\n")
            time.sleep(1)
            valid = phonenumbers.is_valid_number(number)
            if valid == True:
                print (Fore.GREEN + "{} is a valid Phone number".format(phonenumber))
            elif valid == False:
                print ("{} is not a valid Phone number".format(phonenumber))
                self.miscellaneous()
        except phonenumbers.phonenumberutil.NumberParseException:
            print(Fore.RED + "Error!")
 
 
    def googledork(self):
        ua = UserAgent()
        header = {'User-Agent':str(ua.chrome)}
        dork = input("Enter Dork: ")
        numpage = input("Enter number of links to display: ")
        print ("\n")
        found_links = []
        for url in search(dork, stop=int(numpage), user_agent=str(header)):
            found_links.append(url)
        if found_links:
            print ("Found: {} links".format(numpage))
            save = input("Save results to a file (y/n)?: ").lower()
            if save == "y":
                dorklist = input("Filename: ")
                f = open(dorklist, 'w')
                for url in search(dork, stop=int(numpage)):
                    f.writelines(url)
                    f.writelines("\n")
                    f.close()    
                if path.exists(dorklist):
                    print ("File saved successfully")
                if not path.exists(dorklist):
                    print ("File was not saved")
            elif save == "n":
                for url in search(dork, stop=int(numpage), user_agent=str(header)):
                    print(url)
        else:
            print("No links were found")
 
    def sessionscookies(self):
        try:
            host = self.siteconfig()
            print ("\n")
            session = requests.Session()
            resp = session.get(host)
            print (session.cookies)
        except requests.exceptions.MissingSchema:
            print (Fore.RED + "Please use: http://site.com")
 
 
    def findbackup(self):
        try:
            site = self.siteconfig()
            wordlist = input("Enter Wordlist: ")
            print("\n")
            ua = UserAgent()
            header = {'User-Agent':str(ua.chrome)}
            try:
                f = open(wordlist, 'r')
                backupfiles = f.readlines()
            except IOError:
                print (Fore.RED + "File not found")
                self.webinfo()
           
            for backuplist in backupfiles:
                backuplist = backuplist.strip()
                links = site + "/" + backuplist
                response = requests.get(links, headers=header)
                if response.status_code == 200:
                    print (Fore.GREEN + "Found: {}".format(links))
                elif response.status_code == 429:
                    print (Fore.RED + "Too many requests")
                    self.webinfo()
                elif response.status_code == 400:
                    print (Fore.RED + "Bad Request")
                    self.webinfo()
                elif response.status_code == 403:
                    print (Fore.RED + "Forbidden")
                    self.webinfo()
                elif response.status_code == 500:
                    print (Fore.RED + "Internal server error") 
                    self.webinfo()
        except requests.exceptions.MissingSchema:
            print (Fore.RED + "Please use: http://site.com")
 
 
    def techdiscovery(self):
        try:
            site = self.siteconfig()
            print("\n")
            print ("Scanning..." + "\n")
            info = builtwith(site)
            for framework, tech in info.items():
                print (Fore.GREEN + framework, ":", tech)
        except UnicodeDecodeError:
            pass
 
    def spider(self):
        site = self.siteconfig()
        print("\n")
        ua = UserAgent()
        header = {'User-Agent':str(ua.chrome)} 
        try:
            response = requests.get(site, headers=header)
            if response.status_code == 200:
                content = response.content
                links = re.findall('(?:href=")(.*?)"', content.decode('utf-8'))
                for link in links:
                    link = urljoin(site, link)
                    print (Fore.GREEN + link)
            elif response.status_code == 429:
                print (Fore.RED + "Too many requests")
            elif response.status_code == 400:
                print (Fore.RED + "Bad Request")
            elif response.status_code == 403:
                print (Fore.RED + "Forbidden")
            elif response.status_code == 500:
                print (Fore.RED + "Internal server error") 
        except requests.exceptions.ConnectionError:
            print (Fore.RED + "Connection Error")
        except requests.exceptions.MissingSchema:
            print (Fore.RED + "Please use: http://site.com")   
 
 
    def checksite(self):
        try:
            site = self.siteconfig()
            print ("\n")
            ua = UserAgent()
            header = {'User-Agent':str(ua.chrome)}     
            response = requests.get(site, headers=header)
            if response.status_code == 200:
                print (Fore.GREEN + "Site: {} is up!".format(site))
                self.webinfo()
            elif response.status_code == 400:
                print (Fore.RED + "Bad Request")
            elif response.status_code == 404:
                print (Fore.RED + "Not Found")
            elif response.status_code == 403:
                print (Fore.RED + "Forbidden")
            elif response.status_code == 405:
                print (Fore.RED + "Method not allowed")
            elif response.status_code == 404:
                print (Fore.RED + "Not Found")
            elif response.status_code == 423:
                print (Fore.RED + "LOCKED")
            elif response.status_code == 429:
                print (Fore.RED + "Too many requests")
            elif response.status_code == 499:
                print (Fore.RED + "Client closed request")
            elif response.status_code == 500:
                print (Fore.RED + "Server error")
            elif response.status_code == 501:
                print (Fore.RED + "Not implemented")
            elif response.status_code == 502:
                print (Fore.RED + "Bad Gateway")
            elif response.status_code == 503:
                print (Fore.RED + "Service Unavailable")
            elif response.status_code == 511:
                print (Fore.RED + "Network Authentication Required")
            elif response.status_code == 599:
                print (Fore.RED + "Network Connect Timeout Error")
            else:
                print(Fore.RED + response.status_code)
        except requests.exceptions.MissingSchema:
            print (Fore.GREEN + "Please use: http://site.com") 
        except requests.exceptions.ConnectionError:
            print (Fore.RED + "name or service not known")
       
       
 
    def shodansearch(self):
        # shodan script by Sir809
        ask = input("Do you have a Shodan API key?: ").lower()
 
        if ask == "yes":
            pass
        else:
            self.ipinformation()
 
        apikey = input("Enter API key: ")
        try:
            api = Shodan(apikey)
            url = input("Ip:> ")
            print("\n")
            h = api.host(url)
        except shodan.exception.APIError:
            print (Fore.RED + "Invalid API key!")
            self.ipinformation()
        print(Fore.GREEN + '''
            IP: {}
            Country: {}
            City: {}
            ISP: {}
            Org: {}
            Ports: {}
            OS: {}
       
            '''.format(h['ip_str'],h['country_name'],h['city'],h['isp'],h['org'],h['ports'],h['os']))
 
 
    def shellfinder(self):
        site = self.siteconfig()
        wordlist = input("Enter Wordlist: ")
        print("\n")
        try:
            f = open(wordlist, 'r')
            shells = f.readlines()
        except IOError:
            print (Fore.RED + "FIle not found!")
            self.webinfo()
       
        try:
            for shelllist in shells:
                shelllist = shelllist.strip()
                links = site + "/" + shelllist
                response = requests.get(links)
                if response.status_code == 200:
                    print(Fore.GREEN + "Found: {}".format(links))
                elif response.status_code == 429:
                    print (Fore.RED + "Too many requests")
                    self.webinfo()
                elif response.status_code == 400:
                    print (Fore.RED + "Bad Request")
                    self.webinfo()
                elif response.status_code == 403:
                    print (Fore.RED + "Forbidden")
                    self.webinfo()
                elif response.status_code == 500:
                    print (Fore.RED + "Internal server error") 
                    self.webinfo()
        except requests.exceptions.MissingSchema:
            print (Fore.GREEN + "Please use: http://site.com")
               
 
    def finduploads(self):
        upload = ["upload", "uploads", "upload.php", "up", "uploads.php",
        "blog/uploads", "blog/upload.php", "blog/uploads.php"]
        try:
            site = self.siteconfig()
            print ("\n")
            for fileupload in upload:
                fileupload = fileupload.strip()
                uploadlinks = site + "/" + fileupload
                response = requests.get(uploadlinks)
                if response.status_code == 200:
                    print (Fore.GREEN + "Found: {}".format(uploadlinks))
                elif response.status_code == 429:
                    print (Fore.RED + "Too many requests")
                    self.webinfo()
                elif response.status_code == 400:
                    print (Fore.RED + "Bad Request")
                    self.webinfo()
                elif response.status_code == 403:
                    print (Fore.RED + "Forbidden")
                    self.webinfo()
                elif response.status_code == 500:
                    print (Fore.RED + "Internal server error") 
                    self.webinfo()
        except requests.exceptions.MissingSchema:
            print ("Please use: http://wwww.site.com")

 
    def reversednslookup(self):
        ip = self.siteconfig()
        print("\n")
        try:
            reversedns = socket.gethostbyaddr(str(ip))
            print(reversedns[0])
        except socket.error:
            print (Fore.RED + "Error")
 
    def wordpresscheck(self):
        wp = ['wordpress', 'wp-content', 'wp-login', 'wp-login.php', 'wp-admin', 'wp', 'wp-config',
        'wp-config.php', 'wp-mail.php', 'wp-load.php', 'wp-settings.php', 'wp-includes', 'wp-activate.php',
        'wp-cron.php', 'wp-signup.php', 'wp-config-sample.php']
 
        site = self.siteconfig()
        print ("\n")
       
        for wpress in wp:
            wpress = wpress.strip()
            wplinks = site + "/" + wpress
            response = requests.get(wplinks)
            if response.status_code == 200:
                print (Fore.GREEN + "Wordpress directory has been found! {}".format(wplinks))
            elif response.status_code == 429:
                print (Fore.RED + "Too many requests")
                self.webinfo()
            elif response.status_code == 400:
                print (Fore.RED + "Bad Request")
                self.webinfo()
            elif response.status_code == 403:
                print (Fore.RED + "Forbidden")
                self.webinfo()
            elif response.status_code == 500:
                print (Fore.RED + "Internal server error") 
                self.webinfo()
 
    def cloudflarebypass(self):
        domains = ['mail', 'ftp', 'cpanel']
        try:
            site = self.siteconfig()
            print ("\n")
            try:
                ip = socket.gethostbyname(str(site))
            except socket.error:
                pass
            for subdomain in domains:
                subdomains = subdomain.strip()
                subsite = subdomains + site
                try:
                    subip = socket.gethostbyname(subsite)
                    if subip is not ip:
                        print (Fore.GREEN + "Cloudflare has been bypassed!")
                        print (Fore.GREEN + "The real IP is {}".format(subip))
                        time.sleep(1)
                        self.webinfo()
                    else:
                        print ("Could not retrieve the real IP.")
                except socket.error:
                    pass
        except requests.exceptions.MissingSchema:
            print ("Please use: caca.com")
 
    def adminpanelfind(self):
        adminlist = ['admin', 'cpanel', 'phpmyadmin', 'login', 'login.php', 'wp-admin', 'cp', 'master', 'adm', 'member', 'control', 'webmaster',
    'myadmin', 'admin_cp', 'admin_site', 'administratorlogin/', 'adm/', 'admin/account.php', 'admin/index.php', 'admin/login.php', 'admin/admin.php',
    'admin/account.php', 'admin_area/admin.php', 'admin_area/login.php', 'siteadmin/login.php', 'siteadmin/index.php', 'siteadmin/login.html',
    'admin/account.html', 'admin/index.html', 'admin/login.html', 'admin/admin.html']
        try:
            site = self.siteconfig()
            print ("\n")
            ua = UserAgent()
            header = {'User-Agent':str(ua.chrome)}
            for admin in adminlist:
                admin = admin.strip()
                link = site + "/" + admin
                response = requests.get(link, headers=header)
                if response.status_code == 200:
                    print ("Found {}".format(link))
                elif response.status_code == 400:
                    print("{} Not Found".format(link))
                elif response.status_code == 429:
                    print ("Too many requests")
                elif response.status_code == 400:
                    print ("Bad Request")
                elif response.status_code == 403:
                    print ("Forbidden")
                elif response.status_code == 500:
                    print ("Internal server error")
                else:
                    print(f"{Fore.RED} {link}")
        except requests.exceptions.MissingSchema:
            print (Fore.RED + "Please use http:// or https://")
 
    def smtpenum(self):
        wordlist = input("Wordlist: ")
        host = input("Host: ")
        port = input("Port: ")
 
        try:
            f = open(wordlist, 'rb')
            smtplist = f.readlines()
        except IOError:
            print(Fore.RED + "Could not find the file!")
            self.enumeration()
       
        print ("********************")
        print ("Host: " + host)
        print ("Port: " + port)
        print ("Wordlist: " + wordlist)
        print ("Size: " + str(len(smtplist)))
        print ("********************")
        print ("\n")
           
        print ("Verifying Users, Please wait..." + "\n")
           
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, int(port)))   
        except socket.error:
            print (Fore.RED + "Could not connect to host")
        except TimeoutError:
            print (Fore.RED + "Connection timed out")
        except ValueError:
            print (Fore.RED + "Value Error")
           
        try:
            for users in smtplist:
                userlist = users.strip()
                s.sendall(b"VRFY " + userlist + b"\r\n")
                response = s.recv(1024)
               
                if re.match(b"250", response):
                    print ("Found User: " + str(userlist))
                elif re.match(b"550", response):
                    print ("{} NOT found".format(str(userlist)))
        except ConnectionResetError:
            print ("Connection reset by peer")
        f.close()      
        s.close()
 
    def filedownload(self):
        try:
            site = input("URL of the file: ")
            filename = input("Save file as: ")
           
            headers={'User-Agent': 'Mozilla/5.0'}
            req = requests.get(site, headers)
           
            with open(filename, 'wb') as download:
                download.write(req.content)
                print ("File {} has been downloaded".format(filename))
        except requests.exceptions.MissingSchema:
            print ("Please use: http://site.com")
 
    def serviceban(self):
        host = input("IP: ")
        port = input("Port: ")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, int(port)))
            data = s.recv(1024)
            print (data.strip())
            s.close()
        except socket.error:
            print ("Could not connect to host")
 
    def anonftp(self):
        host = input("FTP server: ")
        print ("\n")
        try:
            ftp = ftplib.FTP(host)
            ftp.login('anonymous', 'anonymous')
            print (str(host) + "\033[0;0m Anonymous FTP logon successful")
            time.sleep(2)
            ftp.quit()
        except Exception as e:
            print (str(host) + Fore.RED + " Anonymous FTP logon failed.")
 
 
    def subrute(self):
        host = self.siteconfig()
        if "https://" in host:
            host = host.replace("https://", "")
        if "http://" in host:
            host = host.replace("http://", "")  
        wordlist = input("Enter SubDomain list: ")
        ua = UserAgent()
        header = {'User-Agent':str(ua.chrome)}
        try:
            with open(wordlist, 'r') as f:
                sublist = f.readlines()
                sublist = list(map(lambda s: s.rstrip("\n"),sublist))
        except IOError:
            print (Fore.RED + "File not found")
        try:
            for lines in sublist:
                time.sleep(1.5)
                check = requests.get("https://" + lines + "." + host, headers=header).status_code
                if check == 200:
                    print (Fore.GREEN + "Found: " + lines + "." + host)
        except requests.exceptions.ConnectionError:
            print (Fore.RED + "Connection Refused by Host")
        except UnboundLocalError:
            pass
 
 
    def getoptions(self):
        try:
            host = self.siteconfig()
            print ("\n")
            conn = http.client.HTTPConnection(host)
            conn.connect()
            conn.request('OPTIONS', '/')
            response = conn.getresponse()
            check = response.getheader('allow')
            print (Fore.GREEN + "[OPTIONS]")
            print (response.getheader('allow'))
            if check is None:
                print ("OPTIONS is not available for listing.")
                conn.close()
        except socket.gaierror:
            print (Fore.RED + "Name or service not known")
            time.sleep(2)
        except http.client.InvalidURL:
            print (Fore.RED + "Please use: site.com or www.site.com")
        except ValueError:
            print(Fore.RED + "Enter valid port")
 
    def gethead(self):
        try:
            host = self.siteconfig()
            print ("\n")
            resp = requests.head(host)
            print (resp.headers)
            time.sleep(2)
        except socket.gaierror:
            print (Fore.RED + "Name or service not known")
        except requests.exceptions.MissingSchema:
            print (Fore.RED + "Please use http or https://site.com")
 
    def whoistool(self):
        try:
            host = self.siteconfig()
            w = whois.whois(host)
            for key, value in w.__dict__.items():
                print (Fore.GREEN + key, ":", value)
                time.sleep(2)
        except socket.gaierror:
            print (Fore.RED + "Name or service not known")
 
    def getrobot(self):
        try:
            site = self.siteconfig()
            print ("\n")
            getreq = urlopen(site + "/" + "robots.txt", data=None)
            data = io.TextIOWrapper(getreq, encoding='utf-8')
            print (Fore.GREEN + data.read())
            time.sleep(2)
        except socket.gaierror:
            print (Fore.RED + "Name or service not known")
        except urllib.error.URLError:
            print (Fore.RED + "Name or service not known")
        except ValueError:
            print(Fore.RED + "Unknown URL type, please use: http://site.com")
 
 
    def ipaddressresolv(self):
        try:
            print ("EX: site.com")
            host = self.siteconfig() #Ex: use site.com format
            print ("\n")
            print (Fore.GREEN + "IPv4 Address: " + socket.gethostbyname(host))
        except socket.gaierror:
            print (Fore.RED + "Name or service not known")
        time.sleep(2)
 
    def ipv4tov6(self):
        try:
            ip = input("Enter IP Address: ")
            print ("\n")
            print (Fore.GREEN + ipaddress.IPv6Address('2002::' + ip).compressed)
            time.sleep(2)
        except ipaddress.AddressValueError:
            print (Fore.RED + "IP address not permitted sorry")
 
 
    def grabthebanner(self):
        try:
            host = self.siteconfig()
            port = int(input("Enter Port: "))
            sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sck.connect((host, port))
            print ("STATUS: " + "host is up!" + "\n")
            print ("Grabbing the banner please wait!" + "\n")
            time.sleep(3)
            sck.send(b"HEAD / HTTP/1.0\r\n\r\n")
            data = sck.recv(1024)
            sck.close()
            print (data.strip())
            time.sleep(2)
        except socket.error:
            print (Fore.RED + "Host is not reachable")
        except ValueError:
            pass
 
    def grabthebannerssl(self):
        host = self.siteconfig()
        port = int(input("Enter Port: "))
        try:
            sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssock = ssl.wrap_socket(sck)
            ssock.connect((host, port))
            print ("STATUS: " + "host is up!" + "\n")
            print ("Grabbing the banner please wait!" + "\n")
            time.sleep(3)
            ssock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            data = ssock.recv(1024)
            ssock.close()
            print (data.strip())
            time.sleep(2)
        except socket.error:
            print (Fore.RED + "Host is not reachable")
 
    def dirbrute(self):
        host = self.siteconfig()
        wordlist = input("Enter Wordlist: ")
        try:
            file = open(wordlist, 'r')
            print (Fore.GREEN + "Found: " + wordlist)
            file.close()
        except IOError:
            print (Fore.RED + "Couldn't find " + wordlist)
            self.webinfo()
            pass
       
        ua = UserAgent()
        header = {'User-Agent':str(ua.chrome)}
 
        with open(wordlist, 'r') as f:
            dirblist = f.readlines()
        try:
            for lines in dirblist:
                dirlines = lines.strip()
                links = host + dirlines
                response = requests.get(links, headers=header)
                if response.status_code == 200:
                    print ("Found: {}".format(links))
                elif response.status_code == 429:
                    print (Fore.RED + "Too many requests")
                    self.webinfo()
                elif response.status_code == 400:
                    print (Fore.RED + "Bad Request")
                    self.webinfo()
                elif response.status_code == 403:
                    print (Fore.RED + "Forbidden")
                    self.webinfo()
                elif response.status_code == 500:
                    print (Fore.RED + "Internal server error") 
                    self.webinfo()
                else:
                    print ("Not Found: {}".format(links))
 
        except requests.exceptions.MissingSchema:
            print (Fore.RED + "Please use: http or https://www.site.com/")
        except socket.gaierror:
            print (Fore.RED + "Name or service not known")
 
    def dnslookup(self):
        try:
            host = self.siteconfig()
            if "https://" in host:
                host = host.replace("https://", "")
            if "http://" in host:
                host = host.replace("http://", "")  
            print ("\n")
            info = dns.resolver.query(host, 'MX')
            for rdata in info:
                print (Fore.GREEN + "Host ", rdata.exchange, 'has preference', rdata.preference)
                time.sleep(2)
        except dns.resolver.NoAnswer:
            print (Fore.RED + "Please use: site.com")
        except dns.resolver.NXDOMAIN:
            print (Fore.RED + "Please use: site.com")
 
    def portscanner(self):
        ip = input("IP: ")
        print ("\n")
        print ("Scanning IP: " + ip + " please wait..." + "\n")
        try:
            for port in range(1, 65535):
                sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                data = sck.connect_ex((ip, port))
                if data == 0:
                    print (Fore.GREEN + "Port: " + str(port) + " " + "open")
                sck.close()
        except socket.error:
            print (Fore.RED + "Could not connect to host")
        except KeyboardInterrupt:
            print ("You pressed CTRL+C")
        except ipaddress.AddressValueError:
            print ("IP address not allowed")
    


    def vulnerability(self):
        while True:
            print (Fore.RED + banner)
            print (Fore.RED + "[" + Fore.CYAN + "0" + Fore.RED + "]" + Fore.WHITE + " Nikto")
            print (Fore.RED + "[" + Fore.CYAN + "1" + Fore.RED + "]" + Fore.WHITE + " Nmap")
            print (Fore.RED + "[" + Fore.CYAN + "2" + Fore.RED + "]" + Fore.WHITE + " Shellshock")
            print (Fore.RED + "[" + Fore.CYAN + "3" + Fore.RED + "]" + Fore.WHITE + " HeartBleed")
            print (Fore.RED + "[" + Fore.CYAN + "4" + Fore.RED + "]" + Fore.WHITE + " Drupageddon")
            print (Fore.RED + "[" + Fore.CYAN + "5" + Fore.RED + "]" + Fore.WHITE + " Drupageddon2")
            print (Fore.RED + "[" + Fore.CYAN + "6" + Fore.RED + "]" + Fore.WHITE + " Apache Struts RCE")
            print (Fore.RED + "[" + Fore.CYAN + "7" + Fore.RED + "]" + Fore.WHITE + " XSStrike")
            print (Fore.RED + "<" + Fore.CYAN +"--" + Fore.WHITE + " Back")
            print ("\n")
 
            ipinfocolor = Fore.RED + "(" + Fore.CYAN + "Vulnerability Scan" + Fore.RED + ")"
            prompt = input(Fore.WHITE + "IGF~" + ipinfocolor + Fore.WHITE + "# ")
            if prompt == "config":
                self.config()
            if prompt == "0":
                self.nikto()
            if prompt == "1":
                self.nmapvuln()
            if prompt == "2":
                self.shellshock()
            if prompt == "3":
                self.heartbleedvuln()
            if prompt == "4":
                self.drupageddon()
            if prompt == "5":
                self.drupageddon2()
            if prompt == "6":
                self.apachestruts()
            if prompt == "7":
                self.xsstrike()
            if prompt == "back":
                self.start()    
   
    def enumeration(self):
        while True:
            print (Fore.RED + banner)
 
            print (Fore.RED + "[" + Fore.CYAN + "1" + Fore.RED + "]" + Fore.WHITE + " SMTP Enumeration")
            print (Fore.RED + "[" + Fore.CYAN + "2" + Fore.RED + "]" + Fore.WHITE + " DNS Enumeration")
            print (Fore.RED + "[" + Fore.CYAN + "3" + Fore.RED + "]" + Fore.WHITE + " FTP Anonymous Check")
            print (Fore.RED + "[" + Fore.CYAN + "4" + Fore.RED + "]" + Fore.WHITE + " FTP User Enumeration")
            print (Fore.RED + "[" + Fore.CYAN + "5" + Fore.RED + "]" + Fore.WHITE + " Nmap Scan")
            print (Fore.RED + "<" + Fore.CYAN +"--" + Fore.WHITE + " Back")
            print ("\n")
 
            enumcolor = Fore.RED + "(" + Fore.CYAN + "Enumeration tools" + Fore.RED + ")"
            prompt = input(Fore.WHITE + "IGF~" + enumcolor + Fore.WHITE + "# ")
            if prompt == "config":
                self.config()            
            if prompt == "1":
                self.smtpenum()
            if prompt == "2":
                self.dnsenum()
            if prompt == "3":
                self.anonftp()
            if prompt == "4":
                self.ftpuserenum()  
            if prompt == "5":
                self.NmapScan()
            if prompt == "back":
                self.start()
 
 
    def miscellaneous(self):
        while True:
            print (Fore.RED + banner)
           
            print (Fore.RED + "[" + Fore.CYAN + "1" + Fore.RED + "]" + Fore.WHITE + " Port Scanner")
            print (Fore.RED + "[" + Fore.CYAN + "2" + Fore.RED + "]" + Fore.WHITE + " Service Banner")
            print (Fore.RED + "[" + Fore.CYAN + "3" + Fore.RED + "]" + Fore.WHITE + " Download File")
            print (Fore.RED + "[" + Fore.CYAN + "4" + Fore.RED + "]" + Fore.WHITE + " Google Dork Search")
            print (Fore.RED + "[" + Fore.CYAN + "5" + Fore.RED + "]" + Fore.WHITE + " Phone Number Validation")
            print (Fore.RED + "<" + Fore.CYAN +"--" + Fore.WHITE + " Back")
            print ("\n")
 
            misccolor = Fore.RED + "(" + Fore.CYAN + "Miscellaneous" + Fore.RED + ")"
            prompt = input(Fore.WHITE + "IGF~" + misccolor + Fore.WHITE + "# ")
            if prompt == "config":
                self.config()            
            if prompt == "1":
                self.portscanner()
            if prompt == "2":
                self.serviceban()
            if prompt == "3":
                self.filedownload()
            if prompt == "4":
                self.googledork()
            if prompt == "5":
                self.phonenuminfo()
            if prompt == "back":
                self.start()
 
 
    def ipinformation(self):
        while True:
            print (Fore.RED + banner)
           
            print (Fore.RED + "[" + Fore.CYAN + "1" + Fore.RED + "]" + Fore.WHITE + " IPv4 to IPv6")
            print (Fore.RED + "[" + Fore.CYAN + "2" + Fore.RED + "]" + Fore.WHITE + " Shodan IP info")
            print (Fore.RED + "[" + Fore.CYAN + "3" + Fore.RED + "]" + Fore.WHITE + " MyIP")
            print (Fore.RED + "<" + Fore.CYAN +"--" + Fore.WHITE + " Back")
            print ("\n")
 
            ipinfocolor = Fore.RED + "(" + Fore.CYAN + "IP Information" + Fore.RED + ")"
            prompt = input(Fore.WHITE + "IGF~" + ipinfocolor + Fore.WHITE + "# ")
            if prompt == "config":
                self.config()            
            if prompt == "1":
                self.ipv4tov6()
            if prompt == "2":
                self.shodansearch()
            if prompt == "3":
                self.myip()
            if prompt == "back":
                self.start()
           
 
    def webinfo(self):
        while True:
            print (Fore.RED + banner)
 
            print (Fore.RED + "[" + Fore.CYAN + "1" + Fore.RED + "]" + Fore.WHITE + "  Banner Grabber\t\t" + Fore.RED + "[" + Fore.CYAN + "12" + Fore.RED + "]" + Fore.WHITE + " Cloudflare Bypass")    
            print (Fore.RED + "[" + Fore.CYAN + "2" + Fore.RED + "]" + Fore.WHITE + "  Directory brute\t\t" + Fore.RED + "[" + Fore.CYAN + "13" + Fore.RED + "]" + Fore.WHITE + " Wordpress Dir Finder")
            print (Fore.RED + "[" + Fore.CYAN + "3" + Fore.RED + "]" + Fore.WHITE + "  Subdomain brute\t\t" + Fore.RED + "[" + Fore.CYAN + "14" + Fore.RED + "]" + Fore.WHITE + " Reverse DNS Lookup")
            print (Fore.RED + "[" + Fore.CYAN + "4" + Fore.RED + "]" + Fore.WHITE + "  Reverse IP Lookup\t\t" + Fore.RED + "[" + Fore.CYAN + "15" + Fore.RED + "]" + Fore.WHITE + " Find Uploads")
            print (Fore.RED + "[" + Fore.CYAN + "5" + Fore.RED + "]" + Fore.WHITE + "  Get robots.txt\t\t" + Fore.RED + "[" + Fore.CYAN + "16" + Fore.RED + "]" + Fore.WHITE + " Find Shells")     
            print (Fore.RED + "[" + Fore.CYAN + "6" + Fore.RED + "]" + Fore.WHITE + "  Whois lookup\t\t" + Fore.RED + "[" + Fore.CYAN + "17" + Fore.RED + "]" + Fore.WHITE + " Website Status")    
            print (Fore.RED + "[" + Fore.CYAN + "7" + Fore.RED + "]" + Fore.WHITE + "  HTTP HEAD request\t\t" + Fore.RED + "[" + Fore.CYAN + "18" + Fore.RED + "]" + Fore.WHITE + " Spider: Extract Links")    
            print (Fore.RED + "[" + Fore.CYAN + "8" + Fore.RED + "]" + Fore.WHITE + "  HTTP OPTIONS\t\t" + Fore.RED + "[" + Fore.CYAN + "19" + Fore.RED + "]" + Fore.WHITE + " Technology Discovery")        
            print (Fore.RED + "[" + Fore.CYAN + "9" + Fore.RED + "]" + Fore.WHITE + "  DNS lookup\t\t\t" + Fore.RED + "[" + Fore.CYAN + "20" + Fore.RED + "]" + Fore.WHITE + " Find Backup files")
            print (Fore.RED + "[" + Fore.CYAN + "10" + Fore.RED + "]" + Fore.WHITE + " Find Admin Panel\t\t" + Fore.RED + "[" + Fore.CYAN + "21" + Fore.RED + "]" + Fore.WHITE + " Session Cookies")
            print (Fore.RED + "[" + Fore.CYAN + "11" + Fore.RED + "]" + Fore.WHITE + " Probe Domains\t\t" + Fore.RED + "[" + Fore.CYAN + "22" + Fore.RED + "]" + Fore.WHITE + " CMS Detection")
            print (Fore.RED + "<" + Fore.CYAN +"--" + Fore.WHITE + " Back")
 
 
            print ("\n")
           
            webinfocolor = Fore.RED + "(" + Fore.CYAN + "Web Information" + Fore.RED + ")"
            prompt = input(Fore.WHITE + "IGF~" + webinfocolor + Fore.WHITE + "# ")
            if prompt == "config":
                self.config()            
            if prompt == "1":
                ask = input("HTTP or HTTPS? ")
                if ask == "HTTPS":
                    self.grabthebannerssl()
                else:
                    self.grabthebanner()
            if prompt == "2":
                self.dirbrute()
            if prompt == "3":
                self.subrute()
            if prompt == "4":
                self.ipaddressresolv()
            if prompt == "5":
                self.getrobot()
            if prompt == "6":
                self.whoistool()
            if prompt == "7":
                self.gethead()
            if prompt == "8":
                self.getoptions()
            if prompt == "9":
                self.dnslookup()
            if prompt == "10":
                self.adminpanelfind()
            if prompt == "11":
                self.httprobe()
            if prompt == "12":
                self.cloudflarebypass()
            if prompt == "13":
                self.wordpresscheck()
            if prompt == "14":
                self.reversednslookup()
            if prompt == "15":
                self.finduploads()
            if prompt == "16":
                self.shellfinder()
            if prompt == "17":
                self.checksite()
            if prompt == "18":
                self.spider()
            if prompt == "19":
                self.techdiscovery()
            if prompt == "20":
                self.findbackup()
            if prompt == "21":
                self.sessionscookies()
            if prompt == "22":
                self.cmseek()
            if prompt == "back":
                self.start()
    
 
    def WindowsHax(self):
        while True:
            print (Fore.RED + banner)
 
            print (Fore.RED + "[" + Fore.CYAN + "1" + Fore.RED + "]" + Fore.WHITE + "  Exploit Suggester")  
            print (Fore.RED + "[" + Fore.CYAN + "2" + Fore.RED + "]" + Fore.WHITE + "  Evil-WinRM") 
            print (Fore.RED + "<" + Fore.CYAN +"--" + Fore.WHITE + " Back")
 
            print ("\n")
 
            windowshaxcolor = Fore.RED + "(" + Fore.CYAN + "Windows Exploitation" + Fore.RED + ")"
            prompt = input(Fore.WHITE + "IGF~" + windowshaxcolor + Fore.WHITE + "# ")
            if prompt == "config":
                self.config()            
            if prompt == "1":
                self.windowsexploitation()
            if prompt == "2":
                self.evilwinrm()
            if prompt == "back":
                self.start()
    
    def SubdomainPlayground(self):
        while True:
            print (Fore.RED + banner)
 
            print (Fore.RED + "[" + Fore.CYAN + "1" + Fore.RED + "]" + Fore.WHITE + "  Subrute")  
            print (Fore.RED + "[" + Fore.CYAN + "2" + Fore.RED + "]" + Fore.WHITE + "  CertSpotter") 
            print (Fore.RED + "[" + Fore.CYAN + "3" + Fore.RED + "]" + Fore.WHITE + "  Certsh")  
            print (Fore.RED + "[" + Fore.CYAN + "4" + Fore.RED + "]" + Fore.WHITE + "  Amass") 
            print (Fore.RED + "[" + Fore.CYAN + "5" + Fore.RED + "]" + Fore.WHITE + "  Sublist3r")  
            print (Fore.RED + "[" + Fore.CYAN + "6" + Fore.RED + "]" + Fore.WHITE + "  Knockpy")
            print (Fore.RED + "[" + Fore.CYAN + "7" + Fore.RED + "]" + Fore.WHITE + "  Subfinder")
            print (Fore.RED + "[" + Fore.CYAN + "8" + Fore.RED + "]" + Fore.WHITE + "  Rapiddns")  
            print (Fore.RED + "[" + Fore.CYAN + "9" + Fore.RED + "]" + Fore.WHITE + "  SubOver")      

            print (Fore.RED + "<" + Fore.CYAN +"--" + Fore.WHITE + " Back")
 
            print ("\n")
 
            windowshaxcolor = Fore.RED + "(" + Fore.CYAN + "Subdomain Playground" + Fore.RED + ")"
            prompt = input(Fore.WHITE + "IGF~" + windowshaxcolor + Fore.WHITE + "# ")
            if prompt == "config":
                self.config()            
            if prompt == "1":
                self.subrute()
            if prompt == "2":
                self.spotter()
            if prompt == "3":
                self.certsh()
            if prompt == "4":
                self.amassdomain()
            if prompt == "5":
                self.sublister()
            if prompt == "6":
                self.knockpy()
            if prompt == "7":
                self.subfinder()
            if prompt == "8":
                self.rapiddns()
            if prompt == "9":
                self.subover()
            if prompt == "back":
                self.start()  

    def WPScan(self):
        while True:
            print(Fore.RED + banner)
            
            print (Fore.RED + "[" + Fore.CYAN + "1" + Fore.RED + "]" + Fore.WHITE + "  Normal Scan")  
            print (Fore.RED + "[" + Fore.CYAN + "2" + Fore.RED + "]" + Fore.WHITE + "  User Enumeration") 
            print (Fore.RED + "[" + Fore.CYAN + "3" + Fore.RED + "]" + Fore.WHITE + "  Crack Passwords")    

            print (Fore.RED + "<" + Fore.CYAN +"--" + Fore.WHITE + " Back")
 
            print ("\n")    
 
            windowshaxcolor = Fore.RED + "(" + Fore.CYAN + "Directory Playground" + Fore.RED + ")"
            prompt = input(Fore.WHITE + "IGF~" + windowshaxcolor + Fore.WHITE + "# ")
            if prompt == "config":
                self.config()            
            if prompt == "1":
                self.WPScanNormal()
            if prompt == "2":
                self.WPScanUserEnumeration()
            if prompt == "3":
                self.WPScanPasswords()
            if prompt == "back":
                self.start()     

    def CMSPlayground(self):
        while True:
            print (Fore.RED + banner + "\n")
            print (Fore.RED + "[" + Fore.CYAN + "1" + Fore.RED + "]" + Fore.WHITE + "  CMSeek")  
            print (Fore.RED + "[" + Fore.CYAN + "2" + Fore.RED + "]" + Fore.WHITE + "  CMSmap")  
            print (Fore.RED + "[" + Fore.CYAN + "3" + Fore.RED + "]" + Fore.WHITE + "  WPScan") 


            print (Fore.RED + "<" + Fore.CYAN +"--" + Fore.WHITE + " Back")
 
            print ("\n")

            self.siteconfig()
            windowshaxcolor = Fore.RED + "(" + Fore.CYAN + "CMS Playground" + Fore.RED + ")"
            prompt = input(Fore.WHITE + "IGF~" + windowshaxcolor + Fore.WHITE + "# ")
            if prompt == "00":
                self.config()            
            if prompt == "1":
                self.cmseek()
            if prompt == "2":
                self.cmsmap()
            if prompt == "3":
                self.WPScan()
            if prompt == "back":
                self.start()      


    def SmbPlayground(self):
        while True:
            print(Fore.RED + banner)
            
            print (Fore.RED + "[" + Fore.CYAN + "1" + Fore.RED + "]" + Fore.WHITE + "  Enum4Linux")  
            print (Fore.RED + "[" + Fore.CYAN + "2" + Fore.RED + "]" + Fore.WHITE + "  Lookupsids") 
            print (Fore.RED + "[" + Fore.CYAN + "3" + Fore.RED + "]" + Fore.WHITE + "  Smb Vuln Scan")      
            print (Fore.RED + "[" + Fore.CYAN + "4" + Fore.RED + "]" + Fore.WHITE + "  Smb Client") 
            print (Fore.RED + "<" + Fore.CYAN +"--" + Fore.WHITE + " Back")
 
            print ("\n")
 
            windowshaxcolor = Fore.RED + "(" + Fore.CYAN + "SMB Playground" + Fore.RED + ")"
            prompt = input(Fore.WHITE + "IGF~" + windowshaxcolor + Fore.WHITE + "# ")
            if prompt == "config":
                self.config()            
            if prompt == "1":
                self.enumforlinux()
            if prompt == "2":
                self.lookupsids()
            if prompt == "3":
                self.smbvulnscan()
            if prompt == "4":
                self.smbclient()
            if prompt == "back":
                self.start() 

    def CMExec(self):
        while True:
            print(Fore.RED + banner)
            
            print (Fore.RED + "[" + Fore.CYAN + "1" + Fore.RED + "]" + Fore.WHITE + "  Shares")  
            print (Fore.RED + "[" + Fore.CYAN + "2" + Fore.RED + "]" + Fore.WHITE + "  Passwords") 
            print (Fore.RED + "[" + Fore.CYAN + "3" + Fore.RED + "]" + Fore.WHITE + "  Users")  
            print (Fore.RED + "[" + Fore.CYAN + "4" + Fore.RED + "]" + Fore.WHITE + "  Spider")
            print (Fore.RED + "[" + Fore.CYAN + "5" + Fore.RED + "]" + Fore.WHITE + "  Rid Brute")  
            print (Fore.RED + "<" + Fore.CYAN +"--" + Fore.WHITE + " Back")
 
            print ("\n")    
 
            windowshaxcolor = Fore.RED + "(" + Fore.CYAN + "CMExec" + Fore.RED + ")"
            prompt = input(Fore.WHITE + "IGF~" + windowshaxcolor + Fore.WHITE + "# ")
            if prompt == "config":
                self.config()            
            if prompt == "1":
                self.SMBShares()
            if prompt == "2":
                self.CMEPasswords()
            if prompt == "3":
                self.CMEUser()
            if prompt == "4":
                self.CMESPider()
            if prompt == "5":
                self.CMERid()
            if prompt == "back":
                self.Bruteplayground()
    
    def Patator(self):
        while True:
            print(Fore.RED + banner)
            
            print (Fore.RED + "[" + Fore.CYAN + "1" + Fore.RED + "]" + Fore.WHITE + "  FTP")  
            print (Fore.RED + "[" + Fore.CYAN + "2" + Fore.RED + "]" + Fore.WHITE + "  SSH")   
            print (Fore.RED + "<" + Fore.CYAN +"--" + Fore.WHITE + " Back")

            print ("\n")    
 
            windowshaxcolor = Fore.RED + "(" + Fore.CYAN + "Patator" + Fore.RED + ")"
            prompt = input(Fore.WHITE + "IGF~" + windowshaxcolor + Fore.WHITE + "# ")
            if prompt == "config":
                self.config()            
            if prompt == "1":
                self.patatorFTP()
            if prompt == "2":
                self.patatorSSH()
            if prompt == "back":
                self.Bruteplayground()

    def Hydra(self):
        while True:
            print(Fore.RED + banner)
            
            print (Fore.RED + "[" + Fore.CYAN + "1" + Fore.RED + "]" + Fore.WHITE + "  FTP")  
            print (Fore.RED + "[" + Fore.CYAN + "2" + Fore.RED + "]" + Fore.WHITE + "  SSH") 
            print (Fore.RED + "[" + Fore.CYAN + "3" + Fore.RED + "]" + Fore.WHITE + "  LOGIN")  
            print (Fore.RED + "<" + Fore.CYAN +"--" + Fore.WHITE + " Back")

            print ("\n")    
 
            windowshaxcolor = Fore.RED + "(" + Fore.CYAN + "Hydra" + Fore.RED + ")"
            prompt = input(Fore.WHITE + "IGF~" + windowshaxcolor + Fore.WHITE + "# ")
            if prompt == "config":
                self.config()            
            if prompt == "1":
                self.hydraFTP()
            if prompt == "2":
                self.hydraSSH()
            if prompt == "3":
                self.hydraLOGIN()
            if prompt == "back":
                self.Bruteplayground()

    def Bruteplayground(self):
        while True:
            print(Fore.RED + banner)
            
            print (Fore.RED + "[" + Fore.CYAN + "1" + Fore.RED + "]" + Fore.WHITE + "  Hydra")  
            print (Fore.RED + "[" + Fore.CYAN + "2" + Fore.RED + "]" + Fore.WHITE + "  CrackMapExec") 
            print (Fore.RED + "[" + Fore.CYAN + "3" + Fore.RED + "]" + Fore.WHITE + "  Patator")         

            print (Fore.RED + "<" + Fore.CYAN +"--" + Fore.WHITE + " Back")
 
            print ("\n")    
 
            windowshaxcolor = Fore.RED + "(" + Fore.CYAN + "Brute Playground" + Fore.RED + ")"
            prompt = input(Fore.WHITE + "IGF~" + windowshaxcolor + Fore.WHITE + "# ")
            if prompt == "config":
                self.config()            
            if prompt == "1":
                self.Hydra()
            if prompt == "2":
                self.CMExec()
            if prompt == "3":
                self.Patator()
            if prompt == "back":
                self.start()       
                               
 

    def DirectoryPlayground(self):
        while True:
            print(Fore.RED + banner + "\n")
            self.displayconfig()
            print()
            
            print (Fore.RED + "[" + Fore.CYAN + "1" + Fore.RED + "]" + Fore.WHITE + "  DirSearch")  
            print (Fore.RED + "[" + Fore.CYAN + "2" + Fore.RED + "]" + Fore.WHITE + "  Dirb") 
            print (Fore.RED + "[" + Fore.CYAN + "3" + Fore.RED + "]" + Fore.WHITE + "  Gobuster")    
            print (Fore.RED + "[" + Fore.CYAN + "4" + Fore.RED + "]" + Fore.WHITE + "  Fuff")      

            print (Fore.RED + "<" + Fore.CYAN +"--" + Fore.WHITE + " Back")
            print ("\n")    
 
            windowshaxcolor = Fore.RED + "(" + Fore.CYAN + "Directory Playground" + Fore.RED + ")"
            prompt = input(Fore.WHITE + "IGF~" + windowshaxcolor + Fore.WHITE + "# ")
            if prompt == "config":
                self.config()            
            if prompt == "1":
                self.dirsearch()
            if prompt == "2":
                self.dirb()
            if prompt == "3":
                self.smbvulnscan()
            if prompt == "4":
                self.fuff()
            if prompt == "back":
                self.start()         
                               
                           
 
    def start(self):
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            options = ["01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12", "X"]
            print (Fore.RED + banner)
            print (Fore.RED + "\033[0;0mAuthor  : c0deninja".rjust(30, "="))
            print (Fore.RED + "\033[0;0mDiscord : gotr00t?".rjust(29, "=")+ "\n\n")
 
            print (Fore.RED + "[ " + Fore.CYAN + "IGF Menu" + Fore.RED + " ]" + "\n")   
            self.displayconfig()
            print("\n")
            print (Fore.RED + "[" + Fore.CYAN + "01" + Fore.RED + "] " + Fore.WHITE + "Website Information\t\t" + Fore.RED + "[" + Fore.CYAN + "11" + Fore.RED + "] " + Fore.WHITE + "Tor")
            print (Fore.RED + "[" + Fore.CYAN + "02" + Fore.RED + "] " + Fore.WHITE + "IP Information\t\t\t" + Fore.RED + "[" + Fore.CYAN + "12" + Fore.RED + "] " + Fore.WHITE + "Brute Playground")
            print (Fore.RED + "[" + Fore.CYAN + "03" + Fore.RED + "] " + Fore.WHITE + "Enumeration")
            print (Fore.RED + "[" + Fore.CYAN + "04" + Fore.RED + "] " + Fore.WHITE + "Windows Exploitation")
            print (Fore.RED + "[" + Fore.CYAN + "05" + Fore.RED + "] " + Fore.WHITE + "Subdomain Playground")
            print (Fore.RED + "[" + Fore.CYAN + "06" + Fore.RED + "] " + Fore.WHITE + "SMB Playground")
            print (Fore.RED + "[" + Fore.CYAN + "07" + Fore.RED + "] " + Fore.WHITE + "Directory Playground")
            print (Fore.RED + "[" + Fore.CYAN + "08" + Fore.RED + "] " + Fore.WHITE + "CMS Playground")
            print (Fore.RED + "[" + Fore.CYAN + "09" + Fore.RED + "] " + Fore.WHITE + "Vulnerability Scan")
            print (Fore.RED + "[" + Fore.CYAN + "10" + Fore.RED + "] " + Fore.WHITE + "Miscellaneous")
            print(f"{Fore.RED}[{Fore.CYAN}00{Fore.RED}] {Fore.YELLOW}Update")
            print (Fore.RED + "[" + Fore.CYAN + "X" + Fore.RED + "] " + Fore.WHITE +  " EXIT")
 
            print ("\n")
            startgui = Fore.RED + "(" + Fore.CYAN + "Main" + Fore.RED + ")"
            prompt = input(Fore.WHITE + "IGF~" + startgui + Fore.WHITE + "# ")
            if prompt == "config":
                self.config()
            if prompt == "01":
                self.webinfo()
            if prompt == "02":
                self.ipinformation()
            if prompt == "03":
                self.enumeration()
            if prompt == "04":
                self.WindowsHax()
            if prompt == "05": 
                self.SubdomainPlayground()
            if prompt == "06": 
                self.SmbPlayground()
            if prompt == "07":
                self.DirectoryPlayground()
            if prompt == "08":
                self.CMSPlayground()
            if prompt == "09":
                self.vulnerability()
            if prompt == "10":
                self.miscellaneous()
            if prompt == "11":
                self.torghost()
            if prompt == "12":
                self.Bruteplayground()
            if prompt == "update":
                self.Updates()
            if prompt == "firewall":
                self.DetectFirewall()
            if prompt == "00":
                self.Updates()
            if prompt == "":
                self.start()
            if prompt not in options:
                self.start()
            if "exit" or "x" in prompt.lower():
                sys.exit(0)
