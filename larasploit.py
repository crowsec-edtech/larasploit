#!/usr/bin/env python

import requests, sys, os
import urllib3
urllib3.disable_warnings()
from bs4 import BeautifulSoup

class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def banner():
	print(colors.OKGREEN)
	print("""

______                                     ______     __________ 
___  / ______ _____________ __________________  /________(_)_  /_
__  /  _  __ `/_  ___/  __ `/_  ___/__  __ \_  /_  __ \_  /_  __/
_  /___/ /_/ /_  /   / /_/ /_(__  )__  /_/ /  / / /_/ /  / / /_  
/_____/\__,_/ /_/    \__,_/ /____/ _  .___//_/  \____//_/  \__/  
                                   /_/                           
	- Laravel Automated Vulnerability Scanner
	""")
	print(colors.HEADER)
    # 7468 6 52071 7569 6 574 6 57 2 2 07 9 6f7 5 2062 6 5636f 6 d652 c 206 d 6f 7 2 6 52 0 796 f 7520 6 17265 2 0616 2 6c6 5 20 7 4 6f 2 068 6561 7 20a
def fingerprint(host):
    
    fingerprint_data = []

    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0'}
    proxy = {}

    response = requests.get(host, headers=headers, verify=False, allow_redirects=True)
    print(f'{colors.HEADER}')
    print(f"{colors.OKGREEN} [~] Application Fingerprint {colors.HEADER}\r\n")

    print(f'{colors.OKGREEN} [HTTP STATUS]: {colors.HEADER} {response.status_code}')

    if('Location' in response.headers):
        print(f'{colors.OKGREEN} [HTTP Redirect]: {colors.HEADER} {response.headers["Location"]}')


    if('server' in response.headers and response.headers['Server']):
        fingerprint_data.append({'server': response.headers['server']})

        print(f'{colors.OKGREEN} [Server]: {colors.HEADER} {response.headers["Server"]}')

    if('X-Powered-By' in response.headers and 'PHP' in response.headers['X-Powered-By']):
        fingerprint_data.append({'php_version': response.headers['X-Powered-By']})

        print(f'{colors.OKGREEN} [PHP Version]: {colors.HEADER} {response.headers["X-Powered-By"]}')

    for cookie in dict(response.cookies):
            if('XSRF-TOKEN' in cookie or '_session' in cookie):
                fingerprint_data.append({cookie: response.cookies[cookie]})
                print(f'{colors.OKGREEN} [Common Laravel Cookie]: {colors.HEADER} {cookie}: {response.cookies[cookie][:20]}...')
    
    if('_ignition\/' in response.text):
            fingerprint_data.append({'laravel_default': True})
            fingerprint_data.append({'laravel_ignition': True})

            print(f'{colors.WARNING} [Info]: {colors.HEADER} Laravel 8 detected (with ignition)!')
    
    if('Laravel v8' in response.text):
            fingerprint_data.append({'laravel_default': True})
            print(f'{colors.WARNING} [Info]: {colors.HEADER} Laravel 8 detected!')

    soup = BeautifulSoup(response.text, "html.parser")
    laravel_version = ""
    for searchWrapper in soup.find_all('div', {'class':'ml-4 text-center text-sm text-gray-500 sm:text-right sm:ml-0'}):
        laravel_version = searchWrapper.text.strip()

    if(laravel_version):
        print(f'{colors.WARNING} [Info]: {colors.HEADER} Default laravel instalation detected!')
        print(f'{colors.WARNING} [Version]: {colors.HEADER} {laravel_version}')
        fingerprint_data.append({'laravel_version': laravel_version}    )

    laravel_default = ""
    for searchWrapper in soup.find_all('div', {'class':'title m-b-md'}):
        text = searchWrapper.text.strip()
        if(text == "Laravel"):
            laravel_default = True

    for searchWrapper in soup.find_all('div', {'class':'links'}):
        text = searchWrapper.find('a').text.strip()
        if(text == "Laravel" or text == "Docs"):
            laravel_default = True

    if(laravel_default):
        fingerprint_data.append({'laravel_default': True})
        print(f'{colors.WARNING} [Info]: {colors.HEADER} Default laravel instalation detected!')
        print(f'{colors.WARNING} [Version]: {colors.HEADER} Laravel < 7')

   
    env_testing = requests.get(host + "/.env", headers=headers, verify=False)
    if(env_testing.status_code == 200):
        if('APP_ENV' in env_testing.text):
            print(f"{colors.FAIL} [!] Vulnerability detected: .env file exposed\n")

            for env_line in env_testing.text.split('\n'):
                if('APP_ENV' in env_line):
                    if(env_line != 'APP_ENV=production'):
                        print(f'{colors.WARNING} [Info]: {colors.HEADER} Application running without production mode!')

                if("APP_KEY" in env_line):
                    print(f'{colors.WARNING} [Info]: {colors.HEADER} APP_KEY leaked: {env_line}')

                if("APP_DEBUG" in env_line):
                    if(env_line == "APP_DEBUG=true"):
                        print(f'{colors.WARNING} [Info]: {colors.HEADER} Application running with Debug Mode')
                    else:
                        print(f'{colors.WARNING} [Info]: {colors.HEADER} Application running without Debug Mode')

    return fingerprint_data

def check_requirements():
    fail = False
    if(os.path.isfile('./phpggc/phpggc') == False):
        print(f'{colors.FAIL} [ERR]: {colors.HEADER} Missing phpggc, READ THE FUCKING README!')
        fail = True

    if(fail):
        exit()
def main():
    banner()
    check_requirements()
    if(len(sys.argv) > 1):
        fp = fingerprint(sys.argv[1])
        #print(fp)
    else:
        print(f"{colors.WARNING}[!] USE: {sys.argv[0]} https://target.com\r\n")


if __name__ == "__main__":
    main()