from colorama import Fore, Back, Style
from fake_useragent import UserAgent
from urllib.parse import urljoin
import requests
import sys
import multiprocessing
import re

if len(sys.argv) !=3:
	print ("Usage: python backd00r.py site wordlist")
	sys.exit(1)

site = sys.argv[1]

def findshells():
    ua = UserAgent()
    header = {'User-Agent':str(ua.chrome)}
    try:
        with open(sys.argv[2], "r") as f:
            wordlist = f.readlines()
    except IOError:
        print("File not found")
    
    response = requests.get(site, headers=header)
    
    for shells in wordlist:
        shelllist = shells.strip()
        if response.status_code == 200:
            content = response.content
            links = re.findall('(?:href=")(.*?)"', content.decode('utf-8'))
            for link in links:
                link = urljoin(site, link)
                link2 =  link + "/" + shelllist 
                print(Fore.GREEN + link2)  
processes = []
for _ in range(100):
    process = multiprocessing.Process(target=findshells)
    process.start()
    processes.append(process)
for process in processes:
    process.join()
