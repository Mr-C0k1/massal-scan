#!/usr/bin/env python3
"""
w3scan-gui-upgraded
Antarmuka grafis modern untuk subdomain enumeration dengan fitur lengkap.
Fallback ke CLI jika tkinter tidak tersedia.
"""

import subprocess
import threading
import json
import sys
import os
import time
import queue
import re
from datetime import datetime

# Cek tkinter
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, scrolledtext, messagebox
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False
    print("[INFO] tkinter tidak tersedia. Menjalankan mode CLI fallback.")

# Queue untuk komunikasi thread-safe ke GUI
update_queue = queue.Queue()

def validate_domain(domain):
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    return bool(pattern.match(domain))

class W3ScanGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("W3Scan - Advanced Subdomain Scanner")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)

        # Style
        style = ttk.Style()
        style.theme_use('clam')  # Tema lebih modern

        self.process = None
        self.scan_thread = None

        self.create_widgets()
        self.start_queue_processor()

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding=15)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Input frame
        input_frame = ttk.LabelFrame(main_frame, text="Konfigurasi Scan", padding=10)
        input_frame.pack(fill=tk.X, pady=10)

        # Domain
        ttk.Label(input_frame, text="Target Domain:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.domain_entry = ttk.Entry(input_frame, width=60, font=("Segoe UI", 10))
        self.domain_entry.grid(row=0, column=1, columnspan=2, pady=5, padx=5, sticky=tk.EW)

        # Wordlist
        ttk.Label(input_frame, text="Wordlist (opsional):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.wordlist_entry = ttk.Entry(input_frame, width=60)
        self.wordlist_entry.grid(row=1, column=1, pady=5, padx=5, sticky=tk.EW)
        ttk.Button(input_frame, text="Browse", command=self.browse_wordlist).grid(row=1, column=2, padx=5)

        # Output JSON
        ttk.Label(input_frame, text="Output JSON (opsional):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.output_entry = ttk.Entry(input_frame, width=60)
        self.output_entry.grid(row=2, column=1, pady=5, padx=5, sticky=tk.EW)
        ttk.Button(input_frame, text="Browse", command=self.browse_output).grid(row=2, column=2, padx=5)

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)

        self.start_btn = ttk.Button(button_frame, text="Mulai Scan", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=10)

        self.stop_btn = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=10)

        ttk.Button(button_frame, text="Clear Log", command=self.clear_log).pack(side=tk.RIGHT, padx=10)

        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=5)

        # Status label
        self.status_label = ttk.Label(main_frame, text="Siap", foreground="blue")
        self.status_label.pack(pady=5)

        # Result text
        result_frame = ttk.LabelFrame(main_frame, text="Output Real-time", padding=5)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.result_text = scrolledtext.ScrolledText(
            result_frame, wrap=tk.NONE, font=("Consolas", 10), background="#1e1e1e", foreground="#d4d4d4"
        )
        self.result_text.pack(fill=tk.BOTH, expand=True)

        # Tag warna
        self.result_text.tag_config("info", foreground="#66b3ff")
        self.result_text.tag_config("success", foreground="#90ee90")
        self.result_text.tag_config("error", foreground="#ff6b6b")
        self.result_text.tag_config("timestamp", foreground="#888888")

        # Grid config
        input_frame.columnconfigure(1, weight=1)

    def log(self, message, tag="info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}\n"
        update_queue.put((self.result_text.insert, (tk.END, line, tag)))
        update_queue.put((self.result_text.see, (tk.END,)))

    def browse_wordlist(self):
        path = filedialog.askopenfilename(title="Pilih Wordlist", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self.wordlist_entry.delete(0, tk.END)
            self.wordlist_entry.insert(0, path)

    def browse_output(self):
        default_name = f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path = filedialog.asksaveasfilename(
            title="Simpan Hasil Scan",
            defaultextension=".json",
            initialfile=default_name,
            filetypes=[("JSON files", "*.json")]
        )
        if path:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, path)

    def clear_log(self):
        self.result_text.delete(1.0, tk.END)

    def start_scan(self):
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showwarning("Input Required", "Harap isi domain target!")
            return
        if not validate_domain(domain):
            messagebox.showwarning("Invalid Domain", "Format domain tidak valid!")
            return

        wordlist = self.wordlist_entry.get().strip() or None
        output = self.output_entry.get().strip()

        if not output:
            output = f"results_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            self.output_entry.insert(0, output)

        if not os.path.exists("w3scan_subdomain.py"):
            messagebox.showerror("File Tidak Ditemukan", "w3scan_subdomain.py tidak ditemukan di folder ini!")
            return

        # Build command
        cmd = ["python3", "w3scan_subdomain.py", "--domain", domain]
        if wordlist:
            cmd += ["--wordlist", wordlist]
        cmd += ["--output", output]

        self.clear_log()
        self.log(f"Memulai scan untuk: {domain}", "success")
        self.log(f"Command: {' '.join(cmd)}", "info")

        # UI state
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.start()
        self.status_label.config(text="Scanning...", foreground="orange")

        # Run in thread
        self.scan_thread = threading.Thread(target=self.execute_scan, args=(cmd,), daemon=True)
        self.scan_thread.start()

    def execute_scan(self, cmd):
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            for line in self.process:
                if line.strip():
                    update_queue.put((self.log, (line.rstrip(), "info")))

            self.process.wait()
            returncode = self.process.returncode

            if returncode == 0:
                output_file = cmd[cmd.index("--output") + 1]
                update_queue.put((self.log, (f"\nScan selesai! Hasil disimpan ke: {output_file}", "success")))
                # Load dan tampilkan JSON cantik
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        try:
                            data = json.load(f)
                            pretty_json = json.dumps(data, indent=2, ensure_ascii=False)
                            update_queue.put((self.log, (f"\n=== HASIL AKHIR ===\n{pretty_json}", "success")))
                        except:
                            update_queue.put((self.log, ("Gagal membaca file JSON hasil.", "error")))
            else:
                update_queue.put((self.log, (f"Scan gagal dengan kode error: {returncode}", "error")))

        except Exception as e:
            update_queue.put((self.log, (f"Exception: {str(e)}", "error")))
        finally:
            update_queue.put((self.finalize_scan, ()))

    def stop_scan(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.log("Scan dihentikan oleh user.", "error")
            self.finalize_scan()

    def finalize_scan(self):
        self.progress.stop()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Scan selesai", foreground="green")
        self.process = None

    def start_queue_processor(self):
        def process():
            while True:
                try:
                    func, args = update_queue.get(timeout=0.1)
                    func(*args)
                except queue.Empty:
                    break
            self.root.after(100, process)
        self.root.after(100, process)

# CLI Fallback Mode
def run_cli():
    import argparse
    parser = argparse.ArgumentParser(description="W3Scan - Subdomain Scanner (CLI Mode)")
    parser.add_argument("--domain", required=True, help="Domain target (contoh: example.com)")
    parser.add_argument("--wordlist", help="Path ke file wordlist")
    parser.add_argument("--output", help="File output JSON (default: results_<domain>_<timestamp>.json)")

    args = parser.parse_args()

    if not os.path.exists("w3scan_subdomain.py"):
        print("[!] w3scan_subdomain.py tidak ditemukan!")
        sys.exit(1)

    cmd = ["python3", "w3scan_subdomain.py", "--domain", args.domain]
    if args.wordlist:
        cmd += ["--wordlist", args.wordlist]
    if not args.output:
        args.output = f"results_{args.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    cmd += ["--output", args.output]

    print(f"[+] Memulai scan: {' '.join(cmd)}")
    subprocess.call(cmd)

if __name__ == "__main__":
    if GUI_AVAILABLE:
        root = tk.Tk()
        app = W3ScanGUI(root)
        root.mainloop()
    else:
        run_cli()
