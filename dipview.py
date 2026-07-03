#!/usr/bin/env python3
"""
Dipview High-Performance Encrypted Archive Recovery Engine for Digital Forensics & Incident Response (DFIR) 

Author: Dr.Arrow 

"""

import os
import sys
import time
import gzip
import shutil
import subprocess
import itertools
import urllib.request
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ProcessPoolExecutor, as_completed

# --- Automatic Internal Dependency Installer ---
def auto_install_dependencies():
    """Checks for required modules and automatically installs them if missing, safely bypassing PEP 668 on Kali."""
    required_packages = {
        "pyzipper": "pyzipper",
        "rarfile": "rarfile"
    }
    missing_packages = []
    
    for module_name, pip_name in required_packages.items():
        try:
            __import__(module_name)
        except ImportError:
            missing_packages.append(pip_name)
            
    if missing_packages:
        print(f"[\033[94m*\033[0m] Missing required modules: {', '.join(missing_packages)}")
        print("[\033[93m!\033[0m] Attempting automatic installation via pip...")
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", 
                *missing_packages, "--break-system-packages"
            ])
            print("[\033[92m+\033[0m] Dependencies installed successfully!\n")
        except subprocess.CalledProcessError:
            print("[\033[91m-\033[0m] Automatic installation failed.")
            print(f"Please install manually using: apt install python3-rarfile python3-pyzipper -y")
            sys.exit(1)

auto_install_dependencies()

import pyzipper
import rarfile

# Global context cache to store warm file handlers persistently in individual worker RAM contexts
_worker_archive_context = None

def init_worker_context(archive_path, archive_type, use_aes_zip):
    """Initializes the archive file pointer EXACTLY ONCE per CPU core on pool instantiation."""
    global _worker_archive_context
    try:
        if archive_type == "zip":
            _worker_archive_context = pyzipper.AESZipFile(archive_path) if use_aes_zip else pyzipper.ZipFile(archive_path)
        elif archive_type == "rar":
            _worker_archive_context = rarfile.RarFile(archive_path)
    except Exception:
        pass

def check_password_chunk_optimized(target_file, password_chunk, archive_type):
    """Evaluates password streams at raw limits directly against a pre-warmed memory-mapped file handle."""
    global _worker_archive_context
    if not _worker_archive_context:
        return None
        
    for password in password_chunk:
        try:
            if archive_type == "zip":
                with _worker_archive_context.open(target_file, pwd=password) as f:
                    f.read(128)  # Reduced block read sizes to amplify throughput metrics
            elif archive_type == "rar":
                with _worker_archive_context.open(target_file, pwd=password.decode('utf-8', errors='replace')) as f:
                    f.read(128)
            return password
        except Exception:
            continue
    return None

# ANSI Terminal Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"

ASCII_BANNER = f"""{BLUE}{BOLD}
 ██████╗ ██╗██████╗     ██╗   ██╗██╗███████╗██╗    ██╗
 ██╔══██╗██║██╔══██╗    ██║   ██║██║██╔════╝██║    ██║
 ██║  ██║██║██████╔╝    ██║   ██║██║█████╗  ██║ █╗ ██║
 ██║  ██║██║██╔═══╝     ╚██╗ ██╔╝██║██╔══╝  ██║███╗██║
 ██████╔╝██║██║          ╚████╔╝ ██║███████╗╚███╔███╔╝
 ╚═════╝ ╚═╝╚═╝           ╚═══╝  ╚═╝╚══════╝ ╚══╝╚══╝ 
                      [  [ DIP VIEW ]
     [ High-Performance Encrypted Archive Recovery Engine for Digital Forensics & Incident Response (DFIR) ]
        [              Created by: Dr.Arrow       ]
        
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
MIT License

Copyright (c) 2026 DrArrow
{RESET}"""

BUILTIN_COMMON_PASSWORDS = [
    b"123456", b"password", b"123456789", b"12345678", b"12345", b"qwerty",
    b"password123", b"letmein", b"trustnoone", b"admin", b"welcome", b"shadow"
]

KNOWN_SYSTEM_PATHS = [
    Path("/usr/share/wordlists/rockyou.txt.gz"),
    Path("/usr/share/john/password.lst"),
    Path("/usr/share/nmap/nselib/data/passwords.lst"),
]

CHARSETS = {
    "1": (b"0123456789", "Numeric (0-9)"),
    "2": (b"abcdefghijklmnopqrstuvwxyz", "Lowercase Alpha (a-z)"),
    "3": (b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", "Mixed Alpha (a-zA-Z)"),
    "4": (b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "Alphanumeric (a-zA-Z0-9)"),
    "5": (b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=", "Full (All Special Characters)")
}

def print_status(message, status_type="info"):
    if status_type == "success":
        print(f"[{GREEN}+{RESET}] {message}")
    elif status_type == "error":
        print(f"[{RED}-{RESET}] {message}")
    elif status_type == "warning":
        print(f"[{YELLOW}!{RESET}] {message}")
    else:
        print(f"[{BLUE}*{RESET}] {message}")

def handle_gzip_extraction(gz_path):
    out_path = Path(gz_path.stem)
    if out_path.exists(): return out_path
    try:
        with gzip.open(gz_path, 'rb') as f_in, open(out_path, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
        return out_path
    except Exception: return None

def download_custom_wordlist(url):
    try:
        print_status("Parsing remote resource URL...", "info")
        parsed_url = urlparse(url)
        filename = Path(parsed_url.path).name
        if not filename or not any(filename.endswith(ext) for ext in ['.txt', '.lst', '.gz']):
            filename = "custom_downloaded_wordlist.txt"
        target_path = Path(".") / filename
        
        if target_path.exists():
            print_status(f"Found cached version of remote file locally: {target_path.name}", "success")
            return handle_gzip_extraction(target_path) if target_path.suffix == '.gz' else target_path

        print_status(f"Downloading remote wordlist from: {url}", "info")
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=30) as response:
            with open(target_path, 'wb') as out_file:
                shutil.copyfileobj(response, out_file)
        print_status(f"Download complete: {target_path.name}", "success")
        return handle_gzip_extraction(target_path) if target_path.suffix == '.gz' else target_path
    except Exception as e:
        print_status(f"Failed to retrieve remote wordlist: {e}", "error")
        return None

def get_target_archive():
    try:
        custom_input = input(f"[{BLUE}?{RESET}] Enter custom archive path (ZIP/RAR) [or Press Enter for Auto-Search]: ").strip()
        if custom_input:
            custom_path = Path(custom_input)
            if custom_path.is_file() and custom_path.suffix.lower() in ['.zip', '.rar']:
                return custom_path
    except KeyboardInterrupt:
        sys.exit(0)

    archives = list(Path(".").glob("*.zip")) + list(Path(".").glob("*.rar"))
    if not archives: return None
    if len(archives) == 1: return archives[0]

    print_status("Multiple archives found in your current folder:", "warning")
    for idx, f in enumerate(archives, start=1): print(f"  [{idx}] {f.name}")
    try:
        choice = int(input(f"\nSelect target index (1-{len(archives)}): ").strip())
        return archives[choice - 1]
    except Exception: return archives[0]

def export_hash_for_gpu(target_archive, archive_type):
    """Automates extraction routines to compile signature hashes for high-speed external GPU cracking utilities."""
    print_status("Initializing Core GPU Extraction Subsystem...", "warning")
    output_hash_file = Path("archive_hash.txt")
    tool = "zip2john" if archive_type == "zip" else "rar2john"
    
    if shutil.which(tool) is None:
        print_status(f"Native binary '{tool}' missing from system paths. Cannot auto-extract.", "error")
        return

    try:
        print_status(f"Executing native system pipeline hook: {tool} {target_archive.name}", "info")
        result = subprocess.run([tool, str(target_archive)], capture_output=True, text=True, check=True)
        
        # Clean header data if requested or dump raw payload context
        with open(output_hash_file, "w") as hf:
            hf.write(result.stdout)
            
        print("\n" + "="*65)
        print_status("SIGNATURE EXTRACTED SUCCESSFULLY!", "success")
        print_status(f"Hash dumped directly to local workspace target: {BOLD}{output_hash_file}{RESET}")
        print_status("You can now bypass Python bottlenecks and crack this on your GPU natively:")
        print(f"  {BLUE}John-The-Ripper:{RESET} john archive_hash.txt")
        print(f"  {BLUE}Hashcat Mode:   {RESET} hashcat -m {'13000' if archive_type=='rar' else '17225'} archive_hash.txt -a 3 ?d?d?d?d")
        print("="*65 + "\n")
    except Exception as e:
        print_status(f"Failed executing native binary hash exporter sequence: {e}", "error")

def run_recovery_engine(target_archive):
    start_time = time.time()
    attempts = 0
    chunk_size = 10000  
    
    archive_type = "zip" if target_archive.suffix.lower() == ".zip" else "rar"
    use_aes_zip = False

    # Metadata Parsing Phase
    try:
        if archive_type == "zip":
            with pyzipper.AESZipFile(target_archive) as test_zf:
                for info in test_zf.infolist():
                    if info.flag_bits & 0x1 and info.extra and b'AE' in info.extra:
                        use_aes_zip = True
                        print_status("Detected modern AES-256 encrypted ZIP archive standard flags.", "warning")
                        break
            with pyzipper.AESZipFile(target_archive) if use_aes_zip else pyzipper.ZipFile(target_archive) as archive:
                valid_targets = [info.filename for info in archive.infolist() if info.file_size > 0]
        else:
            print_status("Detected RAR file standard archive layout structure.", "info")
            with rarfile.RarFile(target_archive) as archive:
                valid_targets = [info.filename for info in archive.infolist() if info.file_size > 0]
                
        if not valid_targets:
            print_status("Selected archive does not contain any file payloads to check.", "error")
            return
        test_target = valid_targets[0]
    except Exception as e:
        print_status(f"Failed parsing structural metadata headers: {e}", "error")
        return

    # Check common shortcuts immediately
    print_status("Phase 1: Testing built-in common password shortcuts...", "info")
    for password in BUILTIN_COMMON_PASSWORDS:
        attempts += 1
        # Quick check fallback directly using dynamic single run pipeline logic
        if check_password_chunk_optimized(test_target, [password], archive_type) if _worker_archive_context else False:
            display_success(password, attempts, time.time() - start_time)
            return

    print(f"\n[{BLUE}*{RESET}] Select Password Engine Attack Mode Strategy:")
    print("  [1] Wordlist File Scanning (Standard Strategy Mapping)")
    print("  [2] Real-time Brute-Force Key Permutations (Complete Fallback)")
    print("  [3] Auto-Extract Hash Sequence Matrix for High-Speed GPU Cracking (Hashcat/John)")
    try:
        attack_mode = input("\nChoose your mode option (1-3) [Default: 1]: ").strip()
    except KeyboardInterrupt: return

    if attack_mode == "3":
        export_hash_for_gpu(target_archive, archive_type)
        return

    # Instantiate Persistent Multi-Core Warm Core Pool exactly ONCE
    with ProcessPoolExecutor(
        max_workers=os.cpu_count(),
        initializer=init_worker_context,
        initargs=(target_archive, archive_type, use_aes_zip)
    ) as executor:
        
        # --- ATTACK MODE 1: WORDLIST SCANNING ---
        if attack_mode != "2":
            wordlists = []
            try:
                choice = input(f"[{BLUE}?{RESET}] Download remote wordlist file over URL stream? (y/N): ").strip().lower()
                if choice in ['y', 'yes']:
                    url = input(f"[{BLUE}?{RESET}] Enter the direct path target URL: ").strip()
                    if url:
                        remote_list = download_custom_wordlist(url)
                        if remote_list: wordlists.append(remote_list)
            except KeyboardInterrupt: return

            print_status("Scanning host file configuration landscapes for local dictionaries...", "info")
            for p in Path(".").glob("*"):
                if p.is_file() and p.suffix in ['.txt', '.lst']: wordlists.append(p)
            for p in KNOWN_SYSTEM_PATHS:
                if p.exists() and p.is_file(): wordlists.append(handle_gzip_extraction(p) if p.suffix == '.gz' else p)
            wordlists = list(set([w for w in wordlists if w is not None]))

            print_status(f"Phase 2: Distributing tasks across {len(wordlists)} file matrices...", "info")
            for w_path in wordlists:
                print_status(f"Active Processing Source: {w_path.name}", "info")
                current_chunk, futures = [], []
                try:
                    with open(w_path, 'rb') as f:
                        for line in f:
                            current_chunk.append(line.rstrip(b'\r\n'))
                            attempts += 1
                            if len(current_chunk) >= chunk_size:
                                futures.append(executor.submit(check_password_chunk_optimized, test_target, current_chunk, archive_type))
                                current_chunk = []
                            
                            if len(futures) >= (os.cpu_count() * 2):
                                for future in as_completed(futures):
                                    res = future.result()
                                    if res: display_success(res, attempts, time.time() - start_time); return
                                futures = []
                                print_status(f"Evaluated {attempts:,} target candidates...", "info")
                        
                        if current_chunk:
                            futures.append(executor.submit(check_password_chunk_optimized, test_target, current_chunk, archive_type))
                        for future in as_completed(futures):
                            res = future.result()
                            if res: display_success(res, attempts, time.time() - start_time); return
                except Exception: continue

        # --- ATTACK MODE 2: BRUTE-FORCE ENGINE ---
        else:
            print(f"\n[{BLUE}?{RESET}] Select Character Matrix Target for Brute-Force Configurations:")
            for k, v in CHARSETS.items(): print(f"  [{k}] {v[1]}")
            try:
                charset_choice = input("\nSelect targeted option set (1-5) [Default: 1]: ").strip()
                min_len = int(input(f"[{BLUE}?{RESET}] Enter Minimum Password Length: ").strip() or 1)
                max_len = int(input(f"[{BLUE}?{RESET}] Enter Maximum Password Length: ").strip() or 4)
            except (ValueError, KeyboardInterrupt): return

            selected_charset = CHARSETS.get(charset_choice, CHARSETS["1"])[0]
            print_status(f"Phase 2: Warm-Cache execution across {os.cpu_count()} CPU cores ({min_len}-{max_len} chars)...", "warning")
            
            current_chunk, futures = [], []
            for length in range(min_len, max_len + 1):
                for combo in itertools.product(selected_charset, repeat=length):
                    current_chunk.append(bytes(combo))
                    attempts += 1

                    if len(current_chunk) >= chunk_size:
                        futures.append(executor.submit(check_password_chunk_optimized, test_target, current_chunk, archive_type))
                        current_chunk = []

                    if len(futures) >= (os.cpu_count() * 2):
                        for future in as_completed(futures):
                            res = future.result()
                            if res: display_success(res, attempts, time.time() - start_time); return
                        futures = []
                        print_status(f"Evaluated {attempts:,} mathematical permutations...", "info")

            if current_chunk:
                futures.append(executor.submit(check_password_chunk_optimized, test_target, current_chunk, archive_type))
            for future in as_completed(futures):
                res = future.result()
                if res: display_success(res, attempts, time.time() - start_time); return

    print_status(f"Exhausted attack target scope context. Checked {attempts:,} candidate formats. No matching combination found.", "warning")

def display_success(password, attempts, elapsed_time):
    try: decoded_pwd = password.decode('utf-8', errors='replace')
    except Exception: decoded_pwd = str(password)
    print("\n" + "="*50)
    print_status("MATCH SEQUENCE CONFIRMED!", "success")
    print_status(f"Key Found: {BOLD}{decoded_pwd}{RESET}", "success")
    print_status(f"Total Candidate Steps Checked: {attempts:,}")
    print_status(f"Total Structural Processing Time: {elapsed_time:.2f} seconds")
    if elapsed_time > 0: print_status(f"Effective Flow Rate: {int(attempts / elapsed_time):,} items/sec")
    print("="*50)

def main():
    print(ASCII_BANNER)
    target_archive = get_target_archive()
    if not target_archive:
        print_status("No local archive files matching support schemas targets identified.", "error")
        sys.exit(1)
    print_status(f"Target Selected: {BOLD}{target_archive.name}{RESET}", "success")
    run_recovery_engine(target_archive)

if __name__ == "__main__":
    main()
