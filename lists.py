#!/usr/bin/env python3

import requests

# Inserisci le tue URL e le relative categorie in questa lista di tuple
# (URL, Categoria)
urls_and_categories = [
    ("https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt", "malicious"),
    ("https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt", "malicious"),
    ("https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt", "malicious"),
    ("https://v.firebog.net/hosts/Prigent-Crypto.txt", "malicious"),
    ("https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts", "malicious"),
    ("https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt", "malicious"),
    ("https://phishing.army/download/phishing_army_blocklist_extended.txt", "malicious"),
    ("https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt", "malicious"),
    ("https://v.firebog.net/hosts/RPiList-Malware.txt", "malicious"),
    ("https://v.firebog.net/hosts/RPiList-Phishing.txt", "malicious"),
    ("https://v.firebog.net/hosts/RPiList-Phishing.txt", "malicious"),
    ("https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt", "malicious"),
    ("https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts", "malicious"),
    ("https://urlhaus.abuse.ch/downloads/hostfile/", "malicious"),
    ("https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt", "malicious"),
    ("https://v.firebog.net/hosts/Prigent-Malware.txt", "malicious"),
    ("https://zerodot1.gitlab.io/CoinBlockerLists/hosts_browser", "malicious"),
    ("https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt", "malicious"),
    ("https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts", "malicious"),
    ("https://v.firebog.net/hosts/static/w3kbl.txt", "malicious"),
    ("https://adaway.org/hosts.txt", "advertisement"),
    ("https://v.firebog.net/hosts/AdguardDNS.txt", "advertisement"),
    ("https://v.firebog.net/hosts/AdguardDNS.txt", "advertisement"),
    ("https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt", "advertisement"),
    ("https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt", "advertisement"),
    ("https://v.firebog.net/hosts/Easylist.txt", "advertisement"),
    ("https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext", "advertisement"),
    ("https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts", "advertisement"),
    ("https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts", "advertisement"),
    ("https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts", "advertisement"),
    ("https://raw.githubusercontent.com/andyts93/pihole-italian-list/master/adlist.txt", "advertisement"),
    ("https://github.com/andyts93/pihole-italian-list/blob/master/adlist_pluggable.txt", "advertisement"),
    ("https://v.firebog.net/hosts/Easyprivacy.txt", "privacy"),
    ("https://v.firebog.net/hosts/Prigent-Ads.txt", "privacy"),
    ("https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts", "privacy"),
    ("https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt", "privacy"),
    ("https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt", "privacy"),
    ("https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt", "privacy"),
]

results_by_category = {category: set() for _, category in urls_and_categories}

for url, category in urls_and_categories:
    try:
        blocklist = requests.get(url)
        lines = blocklist.text.split('\n')
        for line in lines:
            if line and not line.startswith('#'):
                results_by_category[category].add(line)
    except requests.RequestException as e:
        print(f"Errore durante la richiesta di URL {url}: {e}")

# Scrivi i risultati nei file corrispondenti
for category, result in results_by_category.items():
    with open(f"{category}.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(result))
