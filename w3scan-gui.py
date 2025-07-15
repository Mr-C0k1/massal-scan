#!/usr/bin/env python3
"""
w3scan-gui
Antarmuka grafis untuk menjalankan subdomain scanner dan melihat hasilnya secara real-time.
Note: Jika tkinter tidak tersedia, skrip akan tetap berjalan di CLI fallback mode.
"""
import subprocess
import threading
import json
import sys

# Cek apakah tkinter tersedia
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, scrolledtext
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False
    print("[INFO] Modul tkinter tidak ditemukan. Menjalankan dalam mode CLI fallback.")

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

            cmd = ["python3", "w3scan_subdomain.py", "--domain", domain]
            if wordlist:
                cmd += ["--wordlist", wordlist]
            if output:
                cmd += ["--output", output]

            self.result_text.insert(tk.END, f"[+] Menjalankan: {' '.join(cmd)}\n")
            threading.Thread(target=self.execute_command, args=(cmd,), daemon=True).start()

        def execute_command(self, cmd):
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in process.stdout:
                self.result_text.insert(tk.END, line)
                self.result_text.see(tk.END)

    if __name__ == '__main__':
        root = tk.Tk()
        app = W3ScanGUI(root)
        root.mainloop()
else:
    def run_cli():
        import argparse
        parser = argparse.ArgumentParser(description="CLI mode fallback untuk w3scan GUI")
        parser.add_argument("--domain", required=True, help="Domain target yang akan dipindai")
        parser.add_argument("--wordlist", help="Wordlist opsional")
        parser.add_argument("--output", help="File JSON untuk menyimpan hasil")
        args = parser.parse_args()

        cmd = ["python3", "w3scan_subdomain.py", "--domain", args.domain]
        if args.wordlist:
            cmd += ["--wordlist", args.wordlist]
        if args.output:
            cmd += ["--output", args.output]

        print(f"[+] Menjalankan: {' '.join(cmd)}")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            print(line, end="")

    if __name__ == '__main__':
        run_cli()
