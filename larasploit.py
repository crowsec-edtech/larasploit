#!/usr/bin/env python

import requests, sys

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
.-.. .- .-. .- ... .--. .-.. --- .. - 

______                                     ______     __________ 
___  / ______ _____________ __________________  /________(_)_  /_
__  /  _  __ `/_  ___/  __ `/_  ___/__  __ \_  /_  __ \_  /_  __/
_  /___/ /_/ /_  /   / /_/ /_(__  )__  /_/ /  / / /_/ /  / / /_  
/_____/\__,_/ /_/    \__,_/ /____/ _  .___//_/  \____//_/  \__/  
                                   /_/                           
	- Laravel Automated Vulnerability Scanner
	""")
	print(colors.HEADER)

