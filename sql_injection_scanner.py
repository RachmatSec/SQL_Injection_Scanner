# Mengimpor modul atau pustaka / library
import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint

# Menginisialisasikan sesi untuk melakukan request dan browser yang digunakan melakukan request
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

# Fungsi untuk mengambil semua form yang akan discan
def get_all_forms(url):
    """Memberi sebuah 'URL' , url tersebut akan mengembalikan semua form dari konten HTML"""
    soup = bs(s.get(url).content, "html.parser")

    # Pengembalian dari soup yang telah diinisialisasikan diatas untuk mencari dan menemukan semua form yang akan discan
    return soup.find_all("form")

# Fungsi untuk mengambil semua detail informasi form dan mengekstraknya
def get_form_details(form):
    details = {}

    # Mengambil form action (url target)
    try:
        action = form.attrs.get("action").lower()
    except:
        # Jika tidak ada form action yang diambil
        action = None

    # Mengambil form method (POST, GET, dan lain-lainnya)
    method = form.attrs.get("method", "get").lower()

    # Mengambil semua input detail seperti type dan name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type " : input_type, "name ": input_name, "value ": input_value})

    # Meletakkan semuanya menjadi sebuah kamus yang menghasilkan
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

# Fungsi untuk memberikan respon jika form tersebut vulnerability atau rentan
def is_vulnerable(response):
    errors = {
        "Kamu memiliki sebuah error pada aturan sql mu"
        "Peringatan !!! : mysql",

        "Tanda kutip yang tidak tertutup setelah charakter string",

        "String yang dikutip tidak dihentikan dengan benar"
    }

    for error in errors:
        if error in response.content.decode().lower():
            return True

    return False

# Fungsi untuk melakukan scan sql injection
def scan_sql_injection(url):
    for c in "\"'":
        # Untuk mencoba melakukan injeksi pada sql
        new_url = f"{url}{c}"
        print('[!] Trying', new_url)

        # Untuk respons dan memberikan link url yang rentan atau vulnerability sql injection
        res = s.get(new_url)
        if is_vulnerable(res):
            print('[+] SQL Injection Vulnerability Terdeteksi, Link: ', new_url)
            return True

    # Untuk menunjukan dimana letak vulnerability - nya
    forms = get_all_forms(url)
    print(f"[+] Terdeteksi {len(forms)} forms on {url}.")

    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            data = {}

            for input_tag in form_details["inputs"]:
                if input_tag["value"] or input_tag["type"] == "hidden":

                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{c}"

                url = urljoin(url, form_details["action"])
                if form_details["method"] == "post":
                    res = s.post(url, data=data)
                elif form_details["mehod"] == "get":
                    res = s.post(url, params = data)

                if is_vulnerable(res):
                    print('[+] SQL Injection Vulnerable Terdeteksi, Link: ', url)
                    print('[+] Form: ')
                    print(form_details)
                    break

# Untuk menjalankan fungsi scan_sql_injection(url)
if __name__ == "__main__":
    import sys
    url = sys.argv[1]
    scan_sql_injection(url)