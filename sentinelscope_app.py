#!/usr/bin/env python3
"""
SentinelScope - A basic malware detection tool using YARA rules
"""

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import yara
import os
import sys
import threading
import time

class SentinelScopeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SentinelScope - Malware Detection Tool")
        self.root.geometry("900x700")
        
        # Load YARA rules
        self.rules = None
        self.load_yara_rules()
        
        # Scanning state
        self.scanning = False
        self.scan_cancelled = False
        
        self.setup_ui()
    
    def load_yara_rules(self):
        """Load YARA rules from rules.yar file"""
        try:
            # Get the directory of the script
            if getattr(sys, 'frozen', False):
                # Running as compiled executable
                bundle_dir = sys._MEIPASS
            else:
                # Running as script
                bundle_dir = os.path.dirname(os.path.abspath(__file__))
            
            rules_path = os.path.join(bundle_dir, 'rules.yar')
            self.rules = yara.compile(filepath=rules_path)
            print(f"YARA rules loaded from: {rules_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load YARA rules: {str(e)}")
    
    def setup_ui(self):
        """Setup the user interface"""
        # Main frame
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = tk.Label(main_frame, text="SentinelScope", 
                              font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 10))
        
        # Scan type selection
        type_frame = tk.Frame(main_frame)
        type_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(type_frame, text="Scan Type:", font=("Arial", 12, "bold")).pack(anchor=tk.W)
        
        self.scan_type = tk.StringVar(value="file")
        scan_type_frame = tk.Frame(type_frame)
        scan_type_frame.pack(fill=tk.X, pady=(5, 0))
        
        tk.Radiobutton(scan_type_frame, text="Single File", variable=self.scan_type, 
                      value="file").pack(side=tk.LEFT)
        tk.Radiobutton(scan_type_frame, text="Directory", variable=self.scan_type, 
                      value="directory").pack(side=tk.LEFT, padx=(20, 0))
        tk.Radiobutton(scan_type_frame, text="Device/Drive", variable=self.scan_type, 
                      value="device").pack(side=tk.LEFT, padx=(20, 0))
        
        # Target selection frame
        target_frame = tk.Frame(main_frame)
        target_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(target_frame, text="Select target to scan:").pack(anchor=tk.W)
        
        select_frame = tk.Frame(target_frame)
        select_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.target_path_var = tk.StringVar()
        self.target_entry = tk.Entry(select_frame, textvariable=self.target_path_var)
        self.target_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        browse_frame = tk.Frame(select_frame)
        browse_frame.pack(side=tk.RIGHT, padx=(5, 0))
        
        tk.Button(browse_frame, text="Browse File", command=self.browse_file).pack(side=tk.TOP)
        tk.Button(browse_frame, text="Browse Dir", command=self.browse_directory).pack(side=tk.TOP, pady=(2, 0))
        
        # Quick access buttons for common devices/directories
        quick_frame = tk.Frame(main_frame)
        quick_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(quick_frame, text="Quick Access:", font=("Arial", 10)).pack(anchor=tk.W)
        
        buttons_frame = tk.Frame(quick_frame)
        buttons_frame.pack(fill=tk.X, pady=(5, 0))
        
        tk.Button(buttons_frame, text="Home", command=lambda: self.set_target(os.path.expanduser("~"))).pack(side=tk.LEFT)
        tk.Button(buttons_frame, text="Desktop", command=lambda: self.set_target(os.path.expanduser("~/Desktop"))).pack(side=tk.LEFT, padx=(5, 0))
        tk.Button(buttons_frame, text="Downloads", command=lambda: self.set_target(os.path.expanduser("~/Downloads"))).pack(side=tk.LEFT, padx=(5, 0))
        tk.Button(buttons_frame, text="Applications", command=lambda: self.set_target("/Applications")).pack(side=tk.LEFT, padx=(5, 0))
        tk.Button(buttons_frame, text="Root (/)", command=lambda: self.set_target("/")).pack(side=tk.LEFT, padx=(5, 0))
        
        # Scan options
        options_frame = tk.Frame(main_frame)
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(options_frame, text="Scan Options:", font=("Arial", 10)).pack(anchor=tk.W)
        
        self.recursive_var = tk.BooleanVar(value=True)
        self.show_clean_var = tk.BooleanVar(value=False)
        self.max_size_var = tk.StringVar(value="100")
        
        opts_frame = tk.Frame(options_frame)
        opts_frame.pack(fill=tk.X, pady=(5, 0))
        
        tk.Checkbutton(opts_frame, text="Recursive scan", variable=self.recursive_var).pack(side=tk.LEFT)
        tk.Checkbutton(opts_frame, text="Show clean files", variable=self.show_clean_var).pack(side=tk.LEFT, padx=(20, 0))
        
        size_frame = tk.Frame(opts_frame)
        size_frame.pack(side=tk.LEFT, padx=(20, 0))
        tk.Label(size_frame, text="Max file size (MB):").pack(side=tk.LEFT)
        tk.Entry(size_frame, textvariable=self.max_size_var, width=8).pack(side=tk.LEFT, padx=(5, 0))
        
        # Control buttons
        control_frame = tk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.scan_button = tk.Button(control_frame, text="Start Scan", command=self.start_scan,
                                    bg="#4CAF50", fg="white", font=("Arial", 12))
        self.scan_button.pack(side=tk.LEFT)
        
        self.cancel_button = tk.Button(control_frame, text="Cancel Scan", command=self.cancel_scan,
                                      bg="#f44336", fg="white", font=("Arial", 12), state="disabled")
        self.cancel_button.pack(side=tk.LEFT, padx=(10, 0))
        
        # Progress bar
        self.progress_var = tk.StringVar(value="Ready to scan")
        self.progress_label = tk.Label(main_frame, textvariable=self.progress_var)
        self.progress_label.pack(pady=(5, 0))
        
        self.progress_bar = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress_bar.pack(fill=tk.X, pady=(5, 10))
        
        # Results area
        tk.Label(main_frame, text="Scan Results:", font=("Arial", 12)).pack(
            anchor=tk.W, pady=(10, 5))
        
        self.results_text = scrolledtext.ScrolledText(main_frame, height=15)
        self.results_text.pack(fill=tk.BOTH, expand=True)
    
    def browse_file(self):
        """Open file browser to select a file"""
        filename = filedialog.askopenfilename(
            title="Select file to scan",
            filetypes=[("All files", "*.*")]
        )
        if filename:
            self.target_path_var.set(filename)
    
    def browse_directory(self):
        """Open directory browser to select a directory"""
        dirname = filedialog.askdirectory(
            title="Select directory to scan"
        )
        if dirname:
            self.target_path_var.set(dirname)
    
    def set_target(self, path):
        """Set the target path for scanning"""
        self.target_path_var.set(path)
    
    def start_scan(self):
        """Start the scanning process in a separate thread"""
        if self.scanning:
            return
            
        target_path = self.target_path_var.get()
        if not target_path:
            messagebox.showwarning("Warning", "Please select a target to scan!")
            return
        
        if not os.path.exists(target_path):
            messagebox.showerror("Error", "Selected target does not exist!")
            return
        
        # Start scanning in background thread
        self.scanning = True
        self.scan_cancelled = False
        self.scan_button.config(state="disabled")
        self.cancel_button.config(state="normal")
        self.progress_bar.start()
        
        scan_thread = threading.Thread(target=self.perform_scan, daemon=True)
        scan_thread.start()
    
    def cancel_scan(self):
        """Cancel the current scan"""
        self.scan_cancelled = True
        self.progress_var.set("Cancelling scan...")
    
    def perform_scan(self):
        """Perform the actual scanning process"""
        try:
            target_path = self.target_path_var.get()
            scan_type = self.scan_type.get()
            
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, f"Starting {scan_type} scan: {target_path}\n")
            self.results_text.insert(tk.END, "=" * 60 + "\n\n")
            
            # Get max file size
            try:
                max_size_mb = float(self.max_size_var.get())
                max_size_bytes = max_size_mb * 1024 * 1024
            except ValueError:
                max_size_bytes = 100 * 1024 * 1024  # Default 100MB
            
            files_to_scan = []
            
            if scan_type == "file":
                if os.path.isfile(target_path):
                    files_to_scan = [target_path]
            else:
                # Directory or device scan
                files_to_scan = self.get_files_to_scan(target_path, max_size_bytes)
            
            total_files = len(files_to_scan)
            scanned_files = 0
            threats_found = 0
            
            self.progress_var.set(f"Found {total_files} files to scan")
            
            for file_path in files_to_scan:
                if self.scan_cancelled:
                    break
                
                scanned_files += 1
                self.progress_var.set(f"Scanning {scanned_files}/{total_files}: {os.path.basename(file_path)}")
                
                try:
                    matches = self.rules.match(file_path)
                    
                    if matches:
                        threats_found += 1
                        self.results_text.insert(tk.END, f"🚨 THREAT DETECTED: {file_path}\n")
                        for match in matches:
                            self.results_text.insert(tk.END, f"  Rule: {match.rule}")
                            if match.meta and 'severity' in match.meta:
                                self.results_text.insert(tk.END, f" (Severity: {match.meta['severity']})")
                            self.results_text.insert(tk.END, "\n")
                        self.results_text.insert(tk.END, "\n")
                    elif self.show_clean_var.get():
                        self.results_text.insert(tk.END, f"✅ Clean: {file_path}\n")
                        
                except Exception as e:
                    self.results_text.insert(tk.END, f"❌ Error scanning {file_path}: {str(e)}\n")
                
                # Update UI periodically
                if scanned_files % 10 == 0:
                    self.root.update_idletasks()
            
            # Scan complete
            if self.scan_cancelled:
                self.results_text.insert(tk.END, "\n" + "=" * 60 + "\n")
                self.results_text.insert(tk.END, "⚠️ SCAN CANCELLED\n")
                self.progress_var.set("Scan cancelled")
            else:
                self.results_text.insert(tk.END, "\n" + "=" * 60 + "\n")
                self.results_text.insert(tk.END, f"📊 SCAN COMPLETE\n")
                self.results_text.insert(tk.END, f"Files scanned: {scanned_files}\n")
                self.results_text.insert(tk.END, f"Threats found: {threats_found}\n")
                
                if threats_found > 0:
                    self.results_text.insert(tk.END, f"\n⚠️ WARNING: {threats_found} potential threats detected!\n")
                else:
                    self.results_text.insert(tk.END, f"\n✅ No threats detected. Target appears clean.\n")
                
                self.progress_var.set(f"Scan complete: {scanned_files} files, {threats_found} threats")
            
        except Exception as e:
            self.results_text.insert(tk.END, f"\n❌ Scan error: {str(e)}\n")
            self.progress_var.set("Scan failed")
        
        finally:
            self.scanning = False
            self.scan_button.config(state="normal")
            self.cancel_button.config(state="disabled")
            self.progress_bar.stop()
    
    def get_files_to_scan(self, target_path, max_size_bytes):
        """Get list of files to scan from target path"""
        files_to_scan = []
        recursive = self.recursive_var.get()
        
        try:
            if os.path.isfile(target_path):
                if os.path.getsize(target_path) <= max_size_bytes:
                    files_to_scan.append(target_path)
            elif os.path.isdir(target_path):
                if recursive:
                    for root, dirs, files in os.walk(target_path):
                        for file in files:
                            if self.scan_cancelled:
                                break
                            file_path = os.path.join(root, file)
                            try:
                                if os.path.getsize(file_path) <= max_size_bytes:
                                    files_to_scan.append(file_path)
                            except (OSError, IOError):
                                # Skip files we can't access
                                continue
                else:
                    # Non-recursive directory scan
                    try:
                        for file in os.listdir(target_path):
                            file_path = os.path.join(target_path, file)
                            if os.path.isfile(file_path):
                                try:
                                    if os.path.getsize(file_path) <= max_size_bytes:
                                        files_to_scan.append(file_path)
                                except (OSError, IOError):
                                    continue
                    except PermissionError:
                        pass
        except Exception as e:
            self.results_text.insert(tk.END, f"Error accessing {target_path}: {str(e)}\n")
        
        return files_to_scan

def main():
    root = tk.Tk()
    app = SentinelScopeApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
