import argparse
import time
import sys
import socket
from colorama import *
from modules.checker import WPChecker
from modules.plugin_scanner import WPPluginScanner
from modules.theme_scanner import WPThemeScanner
from modules.version_scanner import WPVersionScanner
from modules.user_password_finder import WPUserPasswordFinder
from modules.sql_xss_scanner import WPSQLXSSScanner
from modules.bruteforce import WPBruteforce
from modules.database_scanner import WPDatabaseScanner
from modules.user_password_file_scanner import WPUser
init()

# 🎨 Terminal Renkleri
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"

# 🔹 ASCII Çizgiler
LINE = f"{CYAN}╔{'═' * 68}╗{RESET}"
SEPARATOR = f"{CYAN}╠{'═' * 68}╣{RESET}"
BOTTOM = f"{CYAN}╚{'═' * 68}╝{RESET}"

BANNER = f"""
{Fore.BLACK} {Style.BRIGHT}                        
 __ __ ___ __ ___ ___ __ 
 \ V  V / '_ (_-</ -_) _|
  \_/\_/| .__/__/\___\__|
        |_|              
    {Fore.RESET}{CYAN}           wpsec - wordpresssecurity scanner by intSpLoiT{RESET}{Style.RESET_ALL}
"""

class WPScanner:
    def __init__(self, url, mode, log):
        self.url = url.rstrip('/')
        self.ip = self.get_ip()
        self.mode = mode
        self.log = log
        self.results = {}

    def get_ip(self):
        """Hedef sitenin IP adresini alır"""
        try:
            return socket.gethostbyname(self.url.replace("http://", "").replace("https://", ""))
        except socket.gaierror:
            return "Unknown"

    def animate(self, text, delay=0.07):
        """Animasyonlu yazdırma"""
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(delay)
        print()

    def check_wp(self):
        """WordPress olup olmadığını kontrol eder"""
        self.animate(f"📡 │ Checking if {self.url} is a WordPress site...")
        wp_checker = WPChecker(self.url)
        result = wp_checker.run()
    
        if result is None:
            self.results["is_wordpress"] = False
            return False
    
        self.results["is_wordpress"] = result.get("is_wordpress", False)
        return self.results["is_wordpress"]


    def scan_ports(self):
        """Açık portları kontrol eder"""
        ports = [80, 443, 21, 22, 3306, 8080, 1900]
        open_ports = []
        self.animate("🔍 │ Scanning open ports...")
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    if s.connect_ex((self.ip, port)) == 0:
                        open_ports.append(port)
                        print(f"   ├── ✅ Port {port} is OPEN")
            except:
                pass
        self.results["open_ports"] = open_ports

    def run_scan(self):
        """Seçilen modlara göre taramayı yönetir"""
        print()
        print(LINE)
        print(f"🎯 │ Target: {self.url} ({self.ip})")
        print(SEPARATOR)
        try:
            if not self.check_wp():
            	print(f"{RED}❌ │ Not a WordPress site. Exiting...{RESET} Press y/Ctrl+D to pass")
            	sk = input("wp (do you want pass?)[y/N] >").strip().lower()
            	if sk != "y":
            		return
            	pass
        except EOFError:
        	print("PASSİNG")
        	pass
        if self.mode in ["quick", "default", "deep"]:
            self.scan_ports()
        if self.mode in ["default", "deep"]:
            self.animate("🛠 │ Scanning plugins...")
            self.results["plugins"] = WPPluginScanner(self.url).run()
            self.animate("🎨 │ Scanning themes...")
            self.results["themes"] = WPThemeScanner(self.url).run()
            self.animate("🔢 │ Checking WordPress version...")
            self.results["wp_version"] = WPVersionScanner(self.url).run()
        if self.mode == "deep":
            self.animate("🔑 │ Finding users & passwords...")
            self.results["users_passwords"] = WPUserPasswordFinder(self.url).run()
            self.animate("💀 │ Scanning for SQL & XSS vulnerabilities...")
            self.results["sql_xss"] = WPSQLXSSScanner(self.url).run()
            self.animate("🚨 │ Running brute-force attack...")
            self.results["bruteforce"] = WPBruteforce(self.url, self.results["users_passwords"]["users"]).run()
            self.animate("💳| Scanning users database...")
            self.results["db_user"] = WPUser(self.url).run()
        self.show_results()

    def show_results(self):
        """Sonuçları gösterir ve log kaydı alır"""
    
        def print_section(title, icon, data):
            """Verileri özel formatta yazdırır"""
            print(f"\n{icon} {title}:")
            print(f"┌───[ {icon} {title} ]")
            print("│")
            if isinstance(data, list):
                for item in data[:-1]:
                    print(f"├── {item}")
                if data:
                    print(f"└── {data[-1]}")
                else:
                    print(f"└── None")
            else:
                print(f"└── {data if data else 'None'}")

        print_section("WP Version", "📡", self.results.get("wp_version", "N/A"))
        print_section("Open Ports", "🚪", self.results.get("open_ports", []))
        print_section("Plugins", "🔌", self.results.get("plugins", []))
        print_section("Themes", "🎨", self.results.get("themes", []))
        print_section("Users", "🔑", self.results.get("users_passwords", {}).get("users", []))
        print_section("SQL/XSS Vulns", "💀", self.results.get("sql_xss", []))
        print_section("Bruteforce Results", "🚨", self.results.get("bruteforce", "None"))
        print_section("Database Paths", "💳", self.results.get("db_user", None))
        print(f"{GREEN}✅ │ Scan Completed!\n{RESET}")

        if self.log:
            with open("scan_results.log", "w") as f:
                def write_section(title, icon, data):
                    """Verileri log dosyasına özel formatta kaydeder"""
                    f.write(f"\n{icon} {title}:\n")
                    f.write(f"┌───[ {icon} {title} ]\n")
                    f.write("│\n")
                    if isinstance(data, list):
                        for item in data[:-1]:
                            f.write(f"├── {item}\n")
                        if data:
                            f.write(f"└── {data[-1]}\n")
                        else:
                            f.write(f"└── None\n")
                    else:
                        f.write(f"└── {data if data else 'None'}\n")

                write_section("WP Version", "📡", self.results.get("wp_version", "N/A"))
                write_section("Open Ports", "🚪", self.results.get("open_ports", []))
                write_section("Plugins", "🔌", self.results.get("plugins", []))
                write_section("Themes", "🎨", self.results.get("themes", []))
                write_section("Users", "🔑", self.results.get("users_passwords", {}).get("users", []))
                write_section("SQL/XSS Vulns", "💀", self.results.get("sql_xss", []))
                write_section("Bruteforce Results", "🚨", self.results.get("bruteforce", "None"))
                write_section('Database Paths',"💳", self.results.get("db_user",None))
            print(f"{YELLOW}📂 │ Results saved to scan_results.log{RESET}")
        

# Argparse CLI
if __name__ == "__main__":
    print(BANNER)
    print(Fore.BLACK + Style.BRIGHT)

    parser = argparse.ArgumentParser(description="WordPress Security Scanner")
    parser.add_argument("url", help="Target WordPress site URL")
    parser.add_argument("-m", "--mode", choices=["quick", "default", "deep"], default="default", help="Scan mode")
    parser.add_argument("-l", "--log", action="store_true", help="Save results to a log file")

    # Yeni Seçenekler
    parser.add_argument("--sql", action="store_true", help="Run only SQL Injection scan")
    parser.add_argument("--xss", action="store_true", help="Run only XSS scan")
    parser.add_argument("--brute", help="Run only brute-force attack")
    parser.add_argument("--timeout", type=int, default=5, help="Set request timeout (default: 5 seconds)")
    parser.add_argument("--verbose", action="store_true", help="Enable detailed output")

    args = parser.parse_args()
    print(Style.RESET_ALL)

    # Scanner başlatılıyor
    scanner = WPScanner(args.url, args.mode, args.log)

    # Kullanıcı belirli bir tarama türü seçtiyse, sadece o işlemi çalıştır
    if args.sql:
        scanner.animate("💀 │ Running SQL Injection scan...")
        scanner.results["sql_xss"] = WPSQLXSSScanner(args.url, sql_scan=True, timeout=args.timeout).run()
        scanner.show_results()
    elif args.xss:
        scanner.animate("💀 │ Running XSS scan...")
        scanner.results["sql_xss"] = WPSQLXSSScanner(args.url, xss_scan=True, timeout=args.timeout).run()
        scanner.show_results()
    elif args.brute:
        scanner.animate("🚨 │ Running brute-force attack...")
        scanner.results["bruteforce"] = WPBruteforce(args.url,[],password_list=args.brute,timeout=args.timeout).run()
        scanner.show_results()
    else:
        # Normal modda çalıştır
        scanner.run_scan()

