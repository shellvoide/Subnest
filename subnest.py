import sys
import os
import re
import json
import argparse
import requests
from bs4 import BeautifulSoup as soup

class PULL:

    WHITE = '\033[1m\033[0m'
    PURPLE = '\033[1m\033[95m'
    CYAN = '\033[1m\033[96m'
    DARKCYAN = '\033[1m\033[36m'
    BLUE = '\033[1m\033[94m'
    GREEN = '\033[1m\033[92m'
    YELLOW = '\033[1m\033[93m'
    RED = '\033[1m\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    LINEUP = '\033[F'

    def __init__(self):
        if not self.support_colors:
            self.win_colors()

    def support_colors(self):
        plat = sys.platform
        supported_platform = plat != 'Pocket PC' and (plat != 'win32' or \
														'ANSICON' in os.environ)
        is_a_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
        if not supported_platform or not is_a_tty:
            return False
        return True

    def win_colors(self):
        self.WHITE = ''
        self.PURPLE = ''
        self.CYAN = ''
        self.DARKCYAN = ''
        self.BLUE = ''
        self.GREEN = ''
        self.YELLOW = ''
        self.RED = ''
        self.BOLD = ''
        self.UNDERLINE = ''
        self.END = ''

    def start(self, mess=""):
        print(self.YELLOW + "[>] " + self.END + mess + self.END)

    def tab(self, key, mess=""):
        print(self.RED + " -  " + key + ": " + self.END + mess)

    def end(self, mess):
        print(self.GREEN + "[<] " + self.END + mess + self.END)

    def error(self, mess=""):
        print(self.RED + "[-] " + self.END + mess + self.END)

    def exit(self, mess=""):
        sys.exit(self.RED + "[~] " + self.END + mess + self.END)

pull = PULL()

class RECON:

    GHEADERS = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Referer': 'https://otx.alienvault.com/',
        'X-OTX-USM-USER': '0'
    }
    URL_GENERAL = "https://otx.alienvault.com/otxapi/indicator/domain/general/{domain}"

    def __init__(self, prs):
        self.domain = prs.domain
        self.filter_all = prs.filter_all

    def enum_basic(self):
        url = self.URL_GENERAL.format(domain = self.domain)
        pull.start("Requesting Basic Info!")
        r = requests.get(url, headers=self.GHEADERS)

        if r.status_code == 200:
            data = json.loads(r.text)
            pull.tab("Indicator", data["indicator"])
            pull.tab("Alexa", data["alexa"])
            pull.tab("Whois", data["whois"])
            pull.tab("Pulse Count", data["pulse_info"]["count"])
            if len(data["validation"]) and data["validation"][0]["source"] == "alexa":
                pull.tab("Alexa Rank", data["validation"][0]["message"].split(":").strip(" "))
            pull.tab("Sections", ", ".join(data["sections"]))
        else:
            pull.error("Error Requesting Basic Info RS [Invalid Code Received]")

    def engage(self):
        self.enum_basic()

class PARSER:

    DOMREGEX = r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]"

    def __init__(self, prs):
        self.domain = self.v_domain(prs.domain)
        self.filter_all = prs.filter_all

    def v_domain(self, vl):
        if vl:
            if re.match(self.DOMREGEX, vl, re.I):
                return vl
            else:
                pull.exit("Invalid Domain Name Entered!")
        else:
            pull.exit("Domain Name Not Provided!")

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('-d', '--domain', dest="domain", default="", type=str, help="Target Domain")
    parser.add_argument('--all', dest="filter_all", default=False, action="store_true", help="Enumerate everything!")

    parser = parser.parse_args()
    parser = PARSER(parser)

    pull.start("Starting Recon Engine!")
    recon = RECON(parser)
    recon.engage()
    pull.end("Done!")

if __name__ == "__main__":
    main()
