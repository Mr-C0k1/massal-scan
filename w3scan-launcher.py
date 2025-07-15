#!/usr/bin/env python3
"""
w3scan-launcher
Hybrid CLI dan GUI launcher untuk w3scan subdomain, recon URL, dan bypass param testing.
"""
import subprocess
import threading
import json
import sys
import os
import argparse

# ==== Cek ketersediaan GUI ==== 
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, scrolledtext
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

# ==== Fallback CLI Mode untuk otomatisasi recon dan bypass param ====
def run_cli(domain, wordlist=None, output=None):
    subdomain_script = "w3scan_subdomain.py"
    recon_url_script = "modules/recon_url.py"
    param_bypass_script = "modules/param_bypass.py"

    if os.path.isfile(subdomain_script):
        print(f"[+] Menjalankan {subdomain_script} untuk {domain}")
        cmd = ["python3", subdomain_script, "--domain", domain]
        if wordlist:
            cmd += ["--wordlist", wordlist]
        if output:
            cmd += ["--output", output]
        subprocess.run(cmd)
    else:
        print(f"[!] File {subdomain_script} tidak ditemukan, melewati...")

    if os.path.isfile(recon_url_script):
        print(f"\n[+] Menjalankan {recon_url_script} untuk {domain}")
        subprocess.run(["python3", recon_url_script, "--domain", domain])
    else:
        print(f"[!] File {recon_url_script} tidak ditemukan, melewati...")

    if os.path.isfile(param_bypass_script):
        print(f"\n[+] Menjalankan {param_bypass_script} untuk {domain}")
        subprocess.run(["python3", param_bypass_script, "--domain", domain])
    else:
        print(f"[!] File {param_bypass_script} tidak ditemukan, melewati...")

# ==== GUI MODE ==== 
if GUI_AVAILABLE:
    class W3ScanGUI:
        def __init__(self, root):
            self.root = root
            self.root.title("w3scan - Subdomain Scanner GUI")
            self.root.geometry("720x600")
            self.create_widgets()

        def create_widgets(self):
            frame = ttk.Frame(self.root, padding=10)
            frame.pack(fill=tk.BOTH, expand=True)

            ttk.Label(frame, text="Target Domain:").grid(row=0, column=0, sticky=tk.W)
            self.domain_entry = ttk.Entry(frame, width=50)
            self.domain_entry.grid(row=0, column=1, columnspan=2, pady=5)

            ttk.Label(frame, text="Wordlist (opsional):").grid(row=1, column=0, sticky=tk.W)
            self.wordlist_entry = ttk.Entry(frame, width=50)
            self.wordlist_entry.grid(row=1, column=1, pady=5)
            ttk.Button(frame, text="Browse", command=self.browse_wordlist).grid(row=1, column=2)

            ttk.Label(frame, text="Simpan Output JSON (opsional):").grid(row=2, column=0, sticky=tk.W)
            self.output_entry = ttk.Entry(frame, width=50)
            self.output_entry.grid(row=2, column=1, pady=5)
            ttk.Button(frame, text="Browse", command=self.browse_output).grid(row=2, column=2)

            ttk.Button(frame, text="Mulai Scan", command=self.run_scan).grid(row=3, column=1, pady=10)

            self.result_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=25)
            self.result_text.grid(row=4, column=0, columnspan=3, pady=10)

        def browse_wordlist(self):
            path = filedialog.askopenfilename(title="Pilih wordlist")
            if path:
                self.wordlist_entry.delete(0, tk.END)
                self.wordlist_entry.insert(0, path)

        def browse_output(self):
            path = filedialog.asksaveasfilename(title="Simpan output sebagai", defaultextension=".json")
            if path:
                self.output_entry.delete(0, tk.END)
                self.output_entry.insert(0, path)

        def run_scan(self):
            domain = self.domain_entry.get()
            wordlist = self.wordlist_entry.get()
            output = self.output_entry.get()

            if not domain:
                self.result_text.insert(tk.END, "[!] Harap isi domain target.\n")
                return

            subdomain_script = "w3scan_subdomain.py"
            recon_url_script = "modules/recon_url.py"
            param_bypass_script = "modules/param_bypass.py"

            if os.path.isfile(subdomain_script):
                cmd = ["python3", subdomain_script, "--domain", domain]
                if wordlist:
                    cmd += ["--wordlist", wordlist]
                if output:
                    cmd += ["--output", output]
                self.result_text.insert(tk.END, f"[+] Menjalankan: {' '.join(cmd)}\n")
                threading.Thread(target=self.execute_command, args=(cmd,), daemon=True).start()
            else:
                self.result_text.insert(tk.END, f"[!] File {subdomain_script} tidak ditemukan, melewati...\n")

            if os.path.isfile(recon_url_script):
                threading.Thread(target=self.execute_command, args=(["python3", recon_url_script, "--domain", domain],), daemon=True).start()
            else:
                self.result_text.insert(tk.END, f"[!] File {recon_url_script} tidak ditemukan, melewati...\n")

            if os.path.isfile(param_bypass_script):
                threading.Thread(target=self.execute_command, args=(["python3", param_bypass_script, "--domain", domain],), daemon=True).start()
            else:
                self.result_text.insert(tk.END, f"[!] File {param_bypass_script} tidak ditemukan, melewati...\n")

        def execute_command(self, cmd):
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in process.stdout:
                self.result_text.insert(tk.END, line)
                self.result_text.see(tk.END)

# ==== MAIN ENTRY ==== 
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="w3scan launcher (GUI & CLI Hybrid)")
    parser.add_argument("--d", help="Target domain untuk pemindaian")
    parser.add_argument("--wordlist", help="Wordlist opsional untuk subdomain")
    parser.add_argument("--output", help="Output file hasil JSON")
    args = parser.parse_args()

    if args.d:
        run_cli(args.d, args.wordlist, args.output)
    elif GUI_AVAILABLE:
        root = tk.Tk()
        app = W3ScanGUI(root)
        root.mainloop()
    else:
        print("[!] Tidak ada GUI dan argumen domain ditemukan. Harap jalankan dengan --d example.com")
