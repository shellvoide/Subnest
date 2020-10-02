import sys
import os
import re
import json
import signal
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
        mess = str(mess)
        print(self.BOLD + " -  " + str(key) + ": " + self.END + str(mess))

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
    URL_WHOIS   = "https://otx.alienvault.com/otxapi/indicator/domain/whois/{domain}"
    URL_HTTPSCAN= "https://otx.alienvault.com/otxapi/indicator/domain/http_scans/{domain}"
    URL_PDNS    = "https://otx.alienvault.com/otxapi/indicator/domain/passive_dns/{domain}"
    URL_RURL    = "https://otx.alienvault.com/otxapi/indicator/domain/url_list/{domain}?limit=50&page={page}"

    def __init__(self, prs):
        self.domain = prs.domain
        self.filter_all = prs.filter_all

    def enum_basic(self):
        url = self.URL_GENERAL.format(domain = self.domain)
        pull.start("Requesting Basic Info!")
        r = requests.get(url, headers=self.GHEADERS)

        if r.status_code == 200:
            data = json.loads(r.text)
            sys.stdout.write("\n")
            pull.tab("Indicator", data["indicator"])
            pull.tab("Alexa", data["alexa"])
            pull.tab("Whois", data["whois"])
            pull.tab("Pulse Count", data["pulse_info"]["count"])
            if len(data["validation"]) and data["validation"][0]["source"] == "alexa":
                pull.tab("Alexa Rank", data["validation"][0]["message"].split(":").strip(" "))
            pull.tab("Sections", ", ".join(data["sections"]))
            sys.stdout.write("\n")
        else:
            pull.error("Error Requesting Basic Info RS [Invalid Code Received]")

    def enum_whois(self):
        url = self.URL_WHOIS.format(domain = self.domain)
        pull.start("Requesting WHOIS ...")
        r = requests.get(url, headers=self.GHEADERS)

        if r.status_code == 200:
            data = json.loads(r.text)
            sys.stdout.write("\n")
            todisplay = data["data"]
            for key in todisplay:
                pull.tab(key["name"].lstrip(" ").rstrip(" "), key["value"])
            sys.stdout.write("\n")
        else:
            pull.error("Error Getting Whois Information RS [Invalid Code Received]")

    def enum_httpscan(self):
        url = self.URL_HTTPSCAN.format(domain = self.domain)
        pull.start("Requesting HTTP Scan ...")
        r = requests.get(url, headers=self.GHEADERS)

        if r.status_code == 200:
            data = json.loads(r.text)
            sys.stdout.write("\n")
            todisplay = data["data"]
            for key in todisplay:
                pull.tab(key["name"].lstrip(" ").rstrip(" "), key["value"])
            sys.stdout.write("\n")
        else:
            pull.error("Error Getting HTTP Scan Information RS [Invalid Code Received]")

    def enum_pdns(self):
        url = self.URL_PDNS.format(domain = self.domain)
        pull.start("Requesting Passive DNS Scans")
        r = requests.get(url, headers=self.GHEADERS)

        if r.status_code == 200:
            data = json.loads(r.text)
            sys.stdout.write("\n")
            todisplay = data["passive_dns"]
            for key in todisplay:
                pull.tab(key["hostname"] + " -> ", key["address"])
            sys.stdout.write("\n")
        else:
            pull.error("Error Getting Passive DNS Information RS [Invalid Code Received]")

    def show_rurl(self, text):
        data = json.loads(text)["url_list"]
        for url in data:
            pull.tab(url["httpcode"], url["url"])

    def enum_rurl(self):
        url = self.URL_RURL.format(domain = self.domain, page=1)
        r = requests.get(url, headers=self.GHEADERS)
        if r.status_code == 200:
            data = json.loads(r.text)
            if data["actual_size"] > 0:
                result = data["actual_size"] / 50
                if not result.is_integer():
                    result += 2
                result = int(result)
                sys.stdout.write("\n")
                self.show_rurl(r.text)
                for page in range(2, result):
                    url = self.URL_RURL.format(domain = self.domain, page = page)
                    r = requests.get(url, headers=self.GHEADERS)
                    if r.status_code == 200:
                        self.show_rurl(r.text)
                sys.stdout.write("\n")
        else:
            pull.error("Error Getting Related URLS!")

    def engage(self):
        #self.enum_basic()
        #self.enum_whois()
        #self.enum_httpscan()
        #self.enum_pdns()
        self.enum_rurl()

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
