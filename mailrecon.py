#!/usr/bin/env python3
import dns.resolver
from pyfiglet import figlet_format
from termcolor import cprint
resolver = dns.resolver.Resolver()
resolver.nameservers = ['8.8.8.8', '1.1.1.1']
print("""
███╗   ███╗ █████╗ ██╗██╗      ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
████╗ ████║██╔══██╗██║██║      ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██╔████╔██║███████║██║██║█████╗██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║╚██╔╝██║██╔══██║██║██║╚════╝██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║ ╚═╝ ██║██║  ██║██║███████╗ ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
    
                       SPF / DKIM / DMARC Scanner
                         Author: Amine Hanafi
""")

def check_txt_record(domain, prefix=""):
    try:
        query = f"{prefix}.{domain}" if prefix else domain
        answers = resolver.resolve(query, 'TXT')
        return [''.join([part.decode() for part in rdata.strings]) for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        return []
def check_spf(domain):
    records = check_txt_record(domain)
    return "Pass" if any("v=spf1" in record for record in records) else "Fail"

def check_dkim(domain, selectors=["default", "google", "selector1", "mail", "smtp"]):
    for selector in selectors:
        records = check_txt_record(domain, f"{selector}._domainkey")
        if any("v=DKIM1" in record for record in records):
            return f"Pass (Selector: {selector})"
    return "Fail"
def check_dmarc(domain):
    records = check_txt_record(domain, "_dmarc")
    for record in records:
        if "v=DMARC1" in record:
            if "p=reject" in record or "p=quarantine" in record:
                return "Enforced"
            elif "p=none" in record:
                return "None"
    return "Fail"
def main():
    domain = input("Enter domain to check (e.g., offsec.com): ").strip()
    spf_status = check_spf(domain)
    dkim_status = check_dkim(domain)
    dmarc_status = check_dmarc(domain)
    print("\n[🔍] DNS Security Check Results:")
    print(f"   ✅ SPF      : {spf_status}")
    print(f"   ✅ DKIM     : {dkim_status}")
    print(f"   ✅ DMARC    : {dmarc_status}")
if __name__ == "__main__":
    main()