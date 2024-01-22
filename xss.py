# xss.py

import subprocess

def run_xss_scan(target_url):
    try:
        subprocess.check_call(['XSpear', '-u', target_url])
        print("\n[*] XSS scan completed successfully.\n")
    except subprocess.CalledProcessError as e:
        print(f"\n[X] XSS scan failed. Error: {e}\n")
