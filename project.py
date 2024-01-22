import sys
from time import sleep
import requests
import re
import socket
import json
import argparse
import platform
import dns.zone
import warnings
import dns.resolver
import pydig
import os
import urllib3
import whois
from port_scanner import run_nmap
from xss import run_xss_scan
# Output Colours
class c:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    UNDERLINE = '\033[4m'



# Banner Function
def banner():
    print('''
   _____      _                 ______         _             
  / ____|    | |               |  ____|       (_)            
 | |    _   _| |__   ___ _ __  | |__ _   _ ___ _  ___  _ __  
 | |   | | | | '_ \ / _ \ '__| |  __| | | / __| |/ _ \| '_ \ 
 | |___| |_| | |_) |  __/ |    | |  | |_| \__ \ | (_) | | | |
  \_____\__, |_.__/ \___|_|    |_|   \__,_|___/_|\___/|_| |_|
         __/ |                                               
        |___/                                                
        ''')
    print(c.BLUE + "\nPython version: " + c.GREEN + platform.python_version() + c.END)
    print(c.BLUE + "Current OS: " + c.GREEN + platform.system() + " " + platform.release() + c.END)

    internet_check = socket.gethostbyname(socket.gethostname())
    if internet_check == "127.0.0.1":
        if platform.system() == "Windows":
            print(c.BLUE + "Internet connection: " + c.RED + "-" + c.END)
        else:
            print(c.BLUE + "Internet connection: " + c.RED + "✕" + c.END)
    else:
        if platform.system() == "Windows":
            print(c.BLUE + "Internet connection: " + c.GREEN + "+" + c.END)
        else:
            print(c.BLUE + "Internet connection: " + c.GREEN + "✔" + c.END)

    print(c.BLUE + "Target: " + c.GREEN + domain + c.END)
    print(c.PURPLE + "Information gain:  " + c.END)
    print(c.PURPLE + "Scanning:  " + c.END)
    print(c.PURPLE + "Exploitation:  " + c.END)
    print(c.YELLOW + "CyberFusion has started" + c.END)
# Argument parser Function
def parseArgs():
    p = argparse.ArgumentParser(description="CyberFsuion - All in One Recon Tool")
    p.add_argument("--all", help="perform all the enumeration at once (best choice)", action='store_true',
                   required=False)
    p.add_argument("-d", "--domain", help="domain to search its subdomains", required=True)
    p.add_argument("-o", "--output", help="file to store the scan output", required=False)
    p.add_argument("-m", "--mail", help="try to enumerate mail servers", action='store_true', required=False)
    p.add_argument('-e', '--extra', help="look for extra dns information", action='store_true', required=False)
    p.add_argument("-n", "--nameservers", help="try to enumerate the name servers", action='store_true',
                   required=False)
    p.add_argument("-i", "--ip", help="it reports the ip or ips of the domain", action='store_true', required=False)
    p.add_argument('-6', '--ipv6', help="enumerate the ipv6 of the domain", action='store_true', required=False)
    p.add_argument("-w", "--waf", help="discover the WAF of the domain main page", action='store_true', required=False)
    p.add_argument("-r", "--repos",
                   help="try to discover valid repositories and s3 servers of the domain (still improving it)",
                   action='store_true', required=False)
    p.add_argument("-c", "--check", help="check active subdomains and store them into a file", action='store_true',
                   required=False)
    p.add_argument("--enum", help="stealthily enumerate and identify common technologies", action='store_true',
                   required=False)
    p.add_argument("--whois", help="perform a whois query to the domain", action='store_true', required=False)
    p.add_argument("--quiet", help="don't print the banner", action='store_true', required=False)
    p.add_argument("--version", help="display the script version", action='store_true', required=False)
    return p.parse_args()
# Nameservers Function 
def ns_enum(domain, filename):
    f = open(f'{filename}.txt', 'a')
    f.write("\n\n[" +"+" + "] Trying to discover valid name servers...\n")
    print("\n[" +"+" + "] Trying to discover valid name servers...\n" )
    sleep(0.2)
    """
    Query to get NS of the domain
    """
    data = ""
    try:
        data = dns.resolver.resolve(f"{domain}", 'NS')
    except:
        pass
    if data:
        for ns in data:
            print(str(ns))
            f.write(str(ns)+'\n')
    else:
        print("Unable to enumerate")
        f.write("Unable to enumerate")
    f.close()

# IPs discover Function
def ip_enum(domain, filename):
    f = open(f'{filename}.txt', 'a')
    f.write("\n[" + "+" + "] Discovering IPs of the domain...\n")
    print("\n[" + "+" + "] Discovering IPs of the domain...\n")
    sleep(0.2)
    """
    Query to get ips
    """
    data = ""
    try:
        data = dns.resolver.resolve(f"{domain}", 'A')
    except:
        pass
    if data:
        for ip in data:
            ip_text = ip.to_text()
            print(ip_text)
            f.write(ip_text+'\n')
    else:
        f.write("Unable to enumerate")
        print("Unable to enumerate")
    f.close()

# Extra DNS info Function
def txt_enum(domain, filename):
    f = open(f'{filename}.txt', 'a')
    f.write("\n\n[" + "+" + "] Enumerating extra DNS information...\n")
    
    print("\n[" + "+" + "] Enumerating extra DNS information...\n")
    sleep(0.2)
    """
    Query to get extra info about the dns
    """
    data = ""
    try:
        data = dns.resolver.resolve(domain, 'TXT')
    except:
        pass
    if data:
        for info in data:
            info_text = info.to_text()
            print(info_text)
            f.write(info_text+'\n')
    else:
        print("Unable to enumerate")
        f.write("Unable to enumerate")
    f.close()

# Function to discover the IPv6 of the target
def ipv6_enum(domain, filename):
    f = open(f'{filename}.txt', 'a')
    f.write("\n[" + "+" +"] Getting ipv6 of the domain...\n")
    
    print("\n[" + "+" +"] Getting ipv6 of the domain...\n")
    sleep(0.2)
    """
    Query to get ipv6
    """
    data = ""
    try:
        data = pydig.query(domain, 'AAAA')
    except:
        pass
    if data:
        for info in data:
            print(info)
            f.write(info+'\n')
    else:
        print("Unable to enumerate")
        f.write("Unable to enumerate")
    f.close()

# Mail servers Function
def mail_enum(domain, filename):
    f = open(f'{filename}.txt', 'a')
    f.write("\n[" + "+" + "] Finding valid mail servers...\n" )
    
    print("\n[" + "+" + "] Finding valid mail servers...\n" )
    sleep(0.2)
    """
    Query to get mail servers
    """
    data = ""
    try:
        data = dns.resolver.resolve(f"{domain}", 'MX')
    except:
        pass
    if data:
        for server in data:
            d = str(server).split(" ")[1]
            print(d)
            f.write(d+'\n')
    else:
        print("Unable to enumerate")
        f.write("Unable to enumerate")
    f.close()

# Function to enumerate github and cloud
def cloudgitEnum(domain, filename):
    f = open(f'{filename}.txt', 'a')
    f.write("\n\n[" + "+" + "] Looking for git repositories and public development info\n")
    
    print("\n[" + "+" + "] Looking for git repositories and public development info\n")
    sleep(0.2)
    try:
        r = requests.get("https://" + domain + "/.git/", verify=False)
        print("Git repository URL: https://" + domain + "/.git/ - " + str(r.status_code) + " status code")
        f.write("\nGit repository URL: https://" + domain + "/.git/ - " + str(r.status_code) + " status code\n")
    except:
        pass
    try:
        r = requests.get("https://bitbucket.org/" + domain.split(".")[0])
        print("Bitbucket account URL: https://bitbucket.org/" + domain.split(".")[0] + " - " + str(r.status_code) + " status code")
        f.write("\nBitbucket account URL: https://bitbucket.org/" + domain.split(".")[0] + " - " + str(r.status_code) + " status code\n")
    except:
        pass
    try:
        r = requests.get("https://github.com/" + domain.split(".")[0])
        print("Github account URL: https://github.com/" + domain.split(".")[0] + " - " + str(r.status_code) + " status code")
        f.write("\nGithub account URL: https://github.com/" + domain.split(".")[0] + " - " + str(r.status_code) + " status code\n")
        
    except:
        pass
    try:
        r = requests.get("https://gitlab.com/" + domain.split(".")[0])
        print("Gitlab account URL: https://gitlab.com/" + domain.split(".")[0] + " - " + str(r.status_code) + " status code")
        f.write("\nGitlab account URL: https://gitlab.com/" + domain.split(".")[0] + " - " + str(r.status_code) + " status code\n")
    except:
        pass

# Query the domain
def whoisLookup(domain, filename):
    f = open(f'{filename}.txt', 'a')
    f.write("\n[" + "+" + "] Performing Whois lookup...")
    
    print("\n[" + "+" + "] Performing Whois lookup...")
    sleep(0.2)

    try:
        w = whois.whois(domain) # Two different ways to avoid a strange error
    except:
        w = whois.query(domain)
    try:
        print(f"\n{w}")
        f.write(f"\n{w}")
    except:
        print("\nAn error has ocurred or unable to whois " + domain)
        f.write("\nAn error has ocurred or unable to whois " + domain)
    f.close()

# Function to thread when probing active subdomains
def checkStatus(subdomain):
    try:
        r = requests.get("https://" + subdomain, timeout=2)
        # Just check if the web is up and https
        if r.status_code:
            print("https://" + subdomain + "\n")
    except:
        try:
            r = requests.get("http://" + subdomain, timeout=2)
            # Check if is up and http
            if r.status_code:
                print("http://" + subdomain + "\n")
        except:
            pass


# Main Domain Discoverer Function
def SDom(domain,filename):
    print("\n[" +"+" + "] Discovering subdomains using passive techniques...\n")
    sleep(0.1)
    global doms
    doms = []
    """
    Get valid subdomains from crt.sh
    """
    try:
        r = requests.get("https://crt.sh/?q=" + domain + "&output=json", timeout=20)
        formatted_json = json.dumps(json.loads(r.text), indent=4)
        crt_domains = sorted(set(re.findall(r'"common_name": "(.*?)"', formatted_json)))
        # Only append new valid subdomains
        for dom in crt_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)

    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass      
    """
    Get subdomains from AlienVault
    """
    try:
        r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=20)
        alienvault_domains = sorted(set(re.findall(r'"hostname": "(.*?)"', r.text)))
        # Only append new valid subdomains
        for dom in alienvault_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)
    except KeyboardInterrupt:
        sys.exit("\n[!] Interrupt handler received, exiting...\n")
    except:
        pass
    """
    Get subdomains from Hackertarget
    """
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=20)
        hackertarget_domains = re.findall(r'(.*?),', r.text)
        # Only append new valid subdomains
        for dom in hackertarget_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)        
    except KeyboardInterrupt:
        sys.exit("\n[!] Interrupt handler received, exiting...\n")
    except:
        pass    
    """
    Get subdomains from RapidDNS
    """
    try:
        r = requests.get(f"https://rapiddns.io/subdomain/{domain}", timeout=20)
        rapiddns_domains = re.findall(r'target="_blank".*?">(.*?)</a>', r.text)
        # Only append new valid subdomains
        for dom in rapiddns_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)          
    except KeyboardInterrupt:
        sys.exit("\n[!] Interrupt handler received, exiting...\n")
    except:
        pass
    """
    Get subdomains from Riddler
    """
    try:
        r = requests.get(f"https://riddler.io/search/exportcsv?q=pld:{domain}", timeout=20)
        riddler_domains = re.findall(r'\[.*?\]",.*?,(.*?),\[', r.text)
        # Only append new valid subdomains
        for dom in riddler_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)        
    except KeyboardInterrupt:
        sys.exit("\n[!] Interrupt handler received, exiting...\n")
    except:
        pass
    """
    Get subdomains from ThreatMiner
    """
    try:
        r = requests.get(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", timeout=20)
        raw_domains = json.loads(r.content)
        threatminer_domains = raw_domains['results']
        # Only append new valid subdomains
        for dom in threatminer_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)
    except KeyboardInterrupt:
        sys.exit("\n[!] Interrupt handler received, exiting...\n")
    except:
        pass
    """
    Get subdomains from URLScan
    """
    try:
        r = requests.get(f"https://urlscan.io/api/v1/search/?q={domain}", timeout=20)
        urlscan_domains = sorted(set(re.findall(r'https://(.*?).' + domain, r.text)))
        # Only append new valid subdomains
        for dom in urlscan_domains:
            dom = dom + "." + domain
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)        
    except KeyboardInterrupt:
        sys.exit("\n[!] Interrupt handler received, exiting...\n")
    except:
        pass
                
    if filename != None:
        f = open(f'{filename}.txt', "w")
    
    if doms:
        """
        Iterate through the subdomains and check the lenght to print them in a table format
        """
        print("+" + "-"*47 + "+")
        for value in doms:
    
            if len(value) >= 10 and len(value) <= 14:
                print("| " + value + "    \t\t\t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 15 and len(value) <= 19:
                print("| " + value + "\t\t\t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 20 and len(value) <= 24:
                print("| " + value + "   \t\t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 25 and len(value) <= 29:
                print("| " + value + "\t\t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 30 and len(value) <= 34:
                print("| " + value + " \t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 35 and len(value) <= 39:
                print("| " + value + "   \t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 40 and len(value) <= 44:
                print("| " + value + " \t|")
                if filename != None:
                    f.write(value + "\n")
        """
        Print summary
        """
        print("+" + "-"*47 + "+")
        print("\nTotal discovered sudomains: " + str(len(doms)))
        """
        Close file if "-o" parameter was especified
        """
        if filename != None:
            f.close()
            print("\n[" + "+" +"] Output stored in " + filename)
    else:
        print("No subdomains discovered through SSL transparency")

# Check if the given target is active
def checkDomain(domain):

    try:
        addr = socket.gethostbyname(domain)
    except:
        print("\nTarget doesn't exists or is down" )
        sys.exit(1)

# Program workflow starts here
if __name__ == '__main__':

    program_version = 1.7
    urllib3.disable_warnings()
    warnings.simplefilter('ignore')

    if "--version" in sys.argv:
        print("\nAll in One Recon Tool v" + str(program_version) + " - By D3Ext")
        print("Contact me: <d3ext@proton.me>\n")
        sys.exit(0)

    parse = parseArgs()

    # Check domain format
    if "." not in parse.domain:
        print("\nInvalid domain format, example: domain.com" )
        sys.exit(0)


    global domain

    domain = parse.domain
    checkDomain(domain)
    
    # If --output is passed (store subdomains in file)
    if parse.output:
        store_info = 1
        filename = f"outputs/{parse.output}"
    else:
        filename = f"outputs/{domain}"
    
    """
    If --all is passed do all enumeration processes
    """
    if parse.domain and parse.all:

        if domain.startswith('https://'):
            domain = domain.split('https://')[1]
        if domain.startswith('http://'):
            domain = domain.split('http://')[1]
        file = None  # Initialize file outside the try block

        try:
            if not parse.quiet:
                banner()
                # Redirect stdout to a file
                # sys.stdout = open("out.txt", "w")
                # sys.stdout = file  # Redirecting stdout to the file
            #run_xss_scan('https://' + domain)
            
            SDom(domain, filename)
            ns_enum(domain, filename)
            mail_enum(domain, filename)
            ip_enum(domain, filename)
            ipv6_enum(domain, filename)
            txt_enum(domain, filename)
            whoisLookup(domain, filename)
            cloudgitEnum(domain, filename)
            
            f = open(f'{filename}.txt', 'a')
            f.write("\n\n[+] Looking for open ports")

            nmap_results = run_nmap(domain)
            for result in nmap_results:
                print(result)
                f.write(result+'\n')
            f.close()
            try:
                file.close()
            except:
                pass
        except KeyboardInterrupt:
            sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
        sys.exit(0)
        
        

# Close the redirection to the file
sys.stdout.close()
