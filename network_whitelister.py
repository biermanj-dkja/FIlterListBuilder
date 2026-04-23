import customtkinter as ctk
from tkinter import filedialog, messagebox
import threading
import queue
import requests
import tldextract
import csv
import os
import time
import re
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# Path for blocklist cache in a stable user-writable location
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "network-whitelister")
CACHE_FILE = os.path.join(CACHE_DIR, "blocklist_cache.txt")


class NetworkWhitelisterApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Network Traffic Whitelister")
        self.geometry("1000x750")

        # Application State
        self.is_running = False
        self.captured_domains = {}
        self.log_queue = queue.Queue()
        self.easylist_domains = set()
        self._domains_lock = threading.Lock()   # FIX 1: guards captured_domains & easylist_domains
        self._cleanup_called = False             # FIX 2: prevents save_and_cleanup from running twice
        self._local_blocklist_path = ""          # FIX 3: local file chosen on main thread before session starts
        self._wildcard_before_deledao = True     # Stores wildcard state to restore when leaving Deledao/Lightspeed

        self.output_folder = os.path.join(os.path.expanduser("~"), "Downloads")
        self.batch_csv_path = ""

        self.setup_ui()
        self.check_queue()

    def setup_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=2)
        self.grid_rowconfigure(0, weight=1)

        # ================= LEFT PANEL (Controls) =================
        self.controls_frame = ctk.CTkScrollableFrame(self)
        self.controls_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.title_label = ctk.CTkLabel(self.controls_frame, text="Configuration", font=ctk.CTkFont(size=20, weight="bold"))
        self.title_label.pack(pady=(15, 20), padx=10)

        self.mode_var = ctk.StringVar(value="Manual Mode")
        self.mode_selector = ctk.CTkSegmentedButton(self.controls_frame, values=["Manual Mode", "Batch Mode", "Scraper Mode"],
                                                    variable=self.mode_var, command=self.toggle_mode)
        self.mode_selector.pack(pady=10, padx=20, fill="x")

        self.dynamic_frame = ctk.CTkFrame(self.controls_frame, fg_color="transparent")
        self.dynamic_frame.pack(pady=10, padx=20, fill="x")

        self.url_entry = ctk.CTkEntry(self.dynamic_frame, placeholder_text="Enter Target URL (e.g., https://example.com)")
        self.url_entry.pack(fill="x", pady=5)

        self.batch_btn = ctk.CTkButton(self.dynamic_frame, text="Select Credentials CSV", command=self.select_batch_csv)
        self.batch_label = ctk.CTkLabel(self.dynamic_frame, text="No CSV selected", text_color="gray", font=("Arial", 10))

        # --- Scraper Mode Widgets ---
        self.scraper_url_entry = ctk.CTkEntry(self.dynamic_frame, placeholder_text="Enter URL to scrape (e.g., https://example.com)")
        self.scraper_filter_var = ctk.BooleanVar(value=False)
        self.scraper_filter_switch = ctk.CTkSwitch(self.dynamic_frame, text="Filter ad/tracking domains", variable=self.scraper_filter_var)

        self.wildcard_var = ctk.BooleanVar(value=True)
        self.wildcard_switch = ctk.CTkSwitch(self.controls_frame, text="Wildcard Mode (*.domain.com)", variable=self.wildcard_var)
        self.wildcard_switch.pack(pady=(15, 2), padx=20, anchor="w")
        # Info label shown when a product auto-matches subdomains (Deledao, Lightspeed)
        self.wildcard_info_label = ctk.CTkLabel(
            self.controls_frame,
            text="Disabled — this product matches subdomains automatically.",
            text_color="gray",
            font=("Arial", 10)
        )
        # Hidden by default; shown when Deledao or Lightspeed is selected

        self.adlist_label = ctk.CTkLabel(self.controls_frame, text="Ad-list Source:")
        self.adlist_label.pack(padx=20, anchor="w")
        self.adlist_var = ctk.StringVar(value="Cloud Blocklist (Ads/Tracking)")
        self.adlist_dropdown = ctk.CTkOptionMenu(
            self.controls_frame,
            values=["Cloud Blocklist (Ads/Tracking)", "Local File", "None"],
            variable=self.adlist_var,
            command=self.on_adlist_change   # FIX 3: show/hide local file picker reactively
        )
        self.adlist_dropdown.pack(pady=(0, 5), padx=20, fill="x")

        # FIX 3: Local file picker lives on the main thread — shown only when "Local File" is selected
        self.local_blocklist_frame = ctk.CTkFrame(self.controls_frame, fg_color="transparent")
        self.local_blocklist_btn = ctk.CTkButton(self.local_blocklist_frame, text="Select Blocklist File",
                                                  command=self.select_local_blocklist)
        self.local_blocklist_btn.pack(fill="x", pady=(0, 2))
        self.local_blocklist_label = ctk.CTkLabel(self.local_blocklist_frame, text="No file selected",
                                                   text_color="gray", font=("Arial", 10))
        self.local_blocklist_label.pack(fill="x")
        # Hidden by default; revealed when "Local File" is chosen
        self.local_blocklist_frame.pack_forget()

        self.export_label = ctk.CTkLabel(self.controls_frame, text="Export Format:")
        self.export_label.pack(padx=20, anchor="w", pady=(10, 0))

        self.export_format_var = ctk.StringVar(value="Standard")
        self.radio_frame = ctk.CTkFrame(self.controls_frame, fg_color="transparent")
        self.radio_frame.pack(padx=20, fill="x", pady=(0, 15))

        formats = ["Standard", "Securly", "GoGuardian", "Deledao", "Blocksi", "Lightspeed"]
        for i, fmt in enumerate(formats):
            rb = ctk.CTkRadioButton(
                self.radio_frame, text=fmt,
                variable=self.export_format_var, value=fmt,
                command=self.on_format_change
            )
            rb.grid(row=i // 2, column=i % 2, sticky="w", pady=5, padx=2)

        self.output_btn = ctk.CTkButton(self.controls_frame, text="Select Output Folder", command=self.select_output_folder)
        self.output_btn.pack(pady=10, padx=20, fill="x")
        self.output_label = ctk.CTkLabel(self.controls_frame, text=self.output_folder, text_color="gray", font=("Arial", 10))
        self.output_label.pack(padx=20, fill="x")

        self.start_btn = ctk.CTkButton(self.controls_frame, text="Start Session", fg_color="green",
                                        hover_color="darkgreen", command=self.start_session)
        self.start_btn.pack(pady=(20, 10), padx=20, fill="x")

        self.stop_btn = ctk.CTkButton(self.controls_frame, text="Stop & Save", fg_color="red",
                                       hover_color="darkred", state="disabled", command=self.stop_session)
        self.stop_btn.pack(pady=(0, 20), padx=20, fill="x")

        # ================= RIGHT PANEL (Network Log) =================
        self.log_frame = ctk.CTkFrame(self)
        self.log_frame.grid(row=0, column=1, padx=(0, 10), pady=10, sticky="nsew")

        self.log_label = ctk.CTkLabel(self.log_frame, text="Network Log (Real-time)", font=ctk.CTkFont(size=16, weight="bold"))
        self.log_label.pack(pady=(15, 10), padx=10, anchor="w")

        self.log_textbox = ctk.CTkTextbox(self.log_frame, state="disabled", font=("Courier", 12))
        self.log_textbox.pack(padx=10, pady=(0, 10), fill="both", expand=True)

    # ── UI helpers ──────────────────────────────────────────────────────────

    def on_format_change(self):
        """Called when the export format radio selection changes.
        Deledao and Lightspeed force wildcard OFF (and disable the toggle)
        because both auto-match subdomains. Switching away restores the previous state."""
        if self.export_format_var.get() in ("Deledao", "Lightspeed"):
            # Save current wildcard state, then force OFF and disable
            self._wildcard_before_deledao = self.wildcard_var.get()
            self.wildcard_var.set(False)
            self.wildcard_switch.configure(state="disabled")
            self.wildcard_info_label.pack(padx=20, anchor="w", pady=(0, 12))
        else:
            # Restore the saved state and re-enable the toggle
            self.wildcard_var.set(self._wildcard_before_deledao)
            self.wildcard_switch.configure(state="normal")
            self.wildcard_info_label.pack_forget()

    def on_adlist_change(self, value):
        """Show the local file picker only when 'Local File' is selected."""
        if value == "Local File":
            self.local_blocklist_frame.pack(padx=20, fill="x", pady=(0, 10))
        else:
            self.local_blocklist_frame.pack_forget()

    def select_local_blocklist(self):
        """Called on the main thread — safe to open a file dialog."""
        path = filedialog.askopenfilename(title="Select Blocklist File", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if path:
            self._local_blocklist_path = path
            self.local_blocklist_label.configure(text=os.path.basename(path))

    def toggle_mode(self, selected_mode):
        # Hide all dynamic widgets first
        self.url_entry.pack_forget()
        self.batch_btn.pack_forget()
        self.batch_label.pack_forget()
        self.scraper_url_entry.pack_forget()
        self.scraper_filter_switch.pack_forget()

        if selected_mode == "Manual Mode":
            self.url_entry.pack(fill="x", pady=5)
        elif selected_mode == "Batch Mode":
            self.batch_btn.pack(fill="x", pady=5)
            self.batch_label.pack(fill="x")
        else:  # Scraper Mode
            self.scraper_url_entry.pack(fill="x", pady=5)
            self.scraper_filter_switch.pack(anchor="w", pady=(0, 5))

    def select_batch_csv(self):
        path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
        if path:
            self.batch_csv_path = path
            self.batch_label.configure(text=os.path.basename(path))

    def select_output_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.output_folder = folder
            self.output_label.configure(text=folder)

    def write_log(self, message):
        self.log_queue.put(message)

    def check_queue(self):
        while not self.log_queue.empty():
            msg = self.log_queue.get()
            self.log_textbox.configure(state="normal")
            self.log_textbox.insert("end", msg + "\n")
            self.log_textbox.see("end")
            self.log_textbox.configure(state="disabled")
        self.after(100, self.check_queue)

    # ── Session control ──────────────────────────────────────────────────────

    def start_session(self):
        if not self.output_folder:
            messagebox.showwarning("Warning", "Please select an Output Folder first.")
            return

        if self.mode_var.get() == "Manual Mode" and not self.url_entry.get():
            messagebox.showwarning("Warning", "Please enter a Target URL.")
            return

        if self.mode_var.get() == "Batch Mode" and not self.batch_csv_path:
            messagebox.showwarning("Warning", "Please select a Credentials CSV.")
            return

        if self.mode_var.get() == "Scraper Mode" and not self.scraper_url_entry.get():
            messagebox.showwarning("Warning", "Please enter a URL to scrape.")
            return

        # FIX 3: Validate local blocklist selection before thread starts
        if self.adlist_var.get() == "Local File" and not self._local_blocklist_path:
            messagebox.showwarning("Warning", "Please select a Local Blocklist file.")
            return

        self.is_running = True
        self._cleanup_called = False    # FIX 2: reset the double-cleanup guard
        self.captured_domains.clear()
        self.easylist_domains.clear()

        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.mode_selector.configure(state="disabled")

        self.log_textbox.configure(state="normal")
        self.log_textbox.delete("1.0", "end")
        self.log_textbox.configure(state="disabled")

        self.write_log("=== SESSION STARTED ===")
        threading.Thread(target=self.run_backend, daemon=True).start()

    def stop_session(self):
        self.write_log("[System] Stopping session...")
        self.is_running = False

    # ── Backend (runs in daemon thread) ──────────────────────────────────────

    def fetch_easylist(self):
        """Downloads / loads the blocklist. Safe to call from background thread
        because the local file path was already resolved on the main thread."""
        self.write_log("[System] Preparing Blocklist...")
        try:
            if self.adlist_var.get() == "Cloud Blocklist (Ads/Tracking)":
                # FIX 4: Cache file written to ~/.cache/network-whitelister/ (stable, writable)
                os.makedirs(CACHE_DIR, exist_ok=True)
                needs_download = True

                if os.path.exists(CACHE_FILE):
                    file_age = time.time() - os.path.getmtime(CACHE_FILE)
                    if file_age < 14400:
                        self.write_log("[System] Using cached Blocklist (less than 4 hours old).")
                        needs_download = False
                    else:
                        self.write_log("[System] Cached Blocklist is old. Updating...")
                        try:
                            os.remove(CACHE_FILE)
                        except OSError:
                            pass

                if needs_download:
                    self.write_log("[System] Downloading fresh StevenBlack Hosts list...")
                    resp = requests.get("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", timeout=15)
                    with open(CACHE_FILE, "w", encoding="utf-8") as f:
                        f.write(resp.text)
                    self.write_log("[System] Blocklist downloaded and cached.")

                with open(CACHE_FILE, "r", encoding="utf-8") as f:
                    lines = f.readlines()

            elif self.adlist_var.get() == "Local File":
                # FIX 3: Path already chosen on main thread — no filedialog here
                if not self._local_blocklist_path:
                    self.write_log("[System] No local blocklist file selected, skipping ad-filter.")
                    return
                with open(self._local_blocklist_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            else:
                self.write_log("[System] Ad-list disabled.")
                return

            count = 0
            new_domains = set()
            for line in lines:
                line = line.strip().lower()
                if not line or line.startswith("#") or line.startswith("!") or line.startswith("["):
                    continue

                domain = ""

                if line.startswith("0.0.0.0 ") or line.startswith("127.0.0.1 "):
                    parts = line.split()
                    if len(parts) >= 2:
                        domain = parts[1]
                        if domain in ("0.0.0.0", "127.0.0.1", "localhost", "broadcasthost"):
                            continue

                elif line.startswith("||"):
                    rule = line.split("$")[0]
                    domain_part = rule[2:]
                    domain = re.split(r"[\^/:]", domain_part)[0]
                    if domain.startswith("*."):
                        domain = domain[2:]

                elif "." in line and " " not in line and not line.startswith("/"):
                    domain = line

                if domain:
                    new_domains.add(domain)
                    count += 1

            # FIX 1: Write to shared set under lock
            with self._domains_lock:
                self.easylist_domains = new_domains

            self.write_log(f"[System] Loaded {count} ad/tracking domains into filter.")
        except Exception as e:
            self.write_log(f"[Error] Failed to load Blocklist: {e}")

    def run_backend(self):
        if self.adlist_var.get() != "None":
            self.fetch_easylist()

        try:
            # FIX 5: headless for Batch and Scraper modes; headed for Manual Mode
            headless = self.mode_var.get() in ("Batch Mode", "Scraper Mode")

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=headless)
                context = browser.new_context()
                # Network interception only needed for Manual and Batch modes
                if self.mode_var.get() != "Scraper Mode":
                    context.on("request", self.handle_request)
                page = context.new_page()

                if self.mode_var.get() == "Manual Mode":
                    target_url = self.url_entry.get()
                    if not target_url.startswith("http"):
                        target_url = "http://" + target_url

                    self.write_log(f"[System] Navigating to {target_url}")
                    try:
                        page.goto(target_url, wait_until="domcontentloaded")
                    except Exception as e:
                        self.write_log(f"[Error] Navigation failed: {e}")

                    while self.is_running:
                        try:
                            page.wait_for_timeout(500)
                        except Exception:
                            # Browser was closed by the user — exit the loop cleanly
                            self.is_running = False
                            break

                elif self.mode_var.get() == "Batch Mode":
                    self.write_log(f"[System] Starting Batch Mode from {os.path.basename(self.batch_csv_path)}")
                    try:
                        with open(self.batch_csv_path, newline="", encoding="utf-8") as csvfile:
                            reader = csv.DictReader(csvfile)
                            for row in reader:
                                if not self.is_running:
                                    break
                                url = row.get("url", row.get("URL", None))
                                if url:
                                    self.write_log(f"\n[Batch] Loading: {url}")
                                    try:
                                        page.goto(url, wait_until="domcontentloaded")
                                        page.wait_for_timeout(3000)
                                    except Exception as e:
                                        self.write_log(f"[Batch Error] Failed on {url}: {e}")
                    except Exception as e:
                        self.write_log(f"[Error] Could not read CSV: {e}")

                elif self.mode_var.get() == "Scraper Mode":
                    self.run_scraper(page)

                browser.close()
                self.write_log("[System] Browser closed.")

        except Exception as e:
            self.write_log(f"[Fatal Error] Playwright crashed: {e}")
        finally:
            self._trigger_cleanup()

    def run_scraper(self, page):
        """Scrapes all href links from a single page and saves a Domain + Link CSV."""
        target_url = self.scraper_url_entry.get()
        if not target_url.startswith("http"):
            target_url = "http://" + target_url

        self.write_log(f"[Scraper] Loading {target_url}")
        try:
            page.goto(target_url, wait_until="domcontentloaded")
        except Exception as e:
            self.write_log(f"[Scraper Error] Failed to load page: {e}")
            return

        # Collect all href attributes from anchor tags
        hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
        self.write_log(f"[Scraper] Found {len(hrefs)} raw links.")

        apply_filter = self.scraper_filter_var.get()
        if apply_filter and not self.easylist_domains:
            self.write_log("[Scraper] Blocklist not loaded — fetching now...")
            self.fetch_easylist()

        scraped_rows = []
        skipped = 0

        for href in hrefs:
            href = href.strip()
            if not href or href.startswith("javascript:") or href.startswith("mailto:"):
                continue

            parsed = urlparse(href)
            hostname = parsed.hostname
            if not hostname:
                continue
            hostname = hostname.lower()

            extracted = tldextract.extract(href)
            if not extracted.domain:
                continue
            base_domain = f"{extracted.domain}.{extracted.suffix}".lower()

            # Optional blocklist filtering
            if apply_filter:
                domains_to_check = {hostname, base_domain}
                if extracted.subdomain:
                    sub_parts = extracted.subdomain.split(".")
                    for i in range(len(sub_parts)):
                        partial = ".".join(sub_parts[i:])
                        domains_to_check.add(f"{partial}.{base_domain}")
                with self._domains_lock:
                    if any(d in self.easylist_domains for d in domains_to_check):
                        skipped += 1
                        continue

            scraped_rows.append([hostname, href])
            self.write_log(f"[Scraped] {hostname}  <--  {href}")

        if apply_filter:
            self.write_log(f"[Scraper] Filtered out {skipped} ad/tracking links.")
        self.write_log(f"[Scraper] Collected {len(scraped_rows)} links after filtering.")

        # Save scraper CSV immediately (separate from the main whitelist save)
        if scraped_rows and self.output_folder:
            timestamp = time.strftime("%d%m%y-%H%M")
            filename = f"scraped_links_{timestamp}.csv"
            filepath = os.path.join(self.output_folder, filename)
            try:
                with open(filepath, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Domain", "Link"])
                    writer.writerows(scraped_rows)
                self.write_log(f"[Scraper] Saved {len(scraped_rows)} links to {filename}")
            except Exception as e:
                self.write_log(f"[Scraper Error] Failed to save CSV: {e}")
        elif not scraped_rows:
            self.write_log("[Scraper] No links found — nothing to save.")

    def handle_request(self, request):
        if not self.is_running:
            return

        url = request.url
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if not hostname:
            return
        hostname = hostname.lower()

        extracted = tldextract.extract(url)
        if not extracted.domain:
            return

        base_domain = f"{extracted.domain}.{extracted.suffix}".lower()

        domains_to_check = {hostname, base_domain}
        if extracted.subdomain:
            sub_parts = extracted.subdomain.split(".")
            for i in range(len(sub_parts)):
                domains_to_check.add(f"{'.'.join(sub_parts[i:])}.{base_domain}")

        # FIX 1: Read shared set under lock
        with self._domains_lock:
            is_blocked = any(d in self.easylist_domains for d in domains_to_check)

        if is_blocked:
            return

        if self.wildcard_var.get():
            final_domain = f"*.{base_domain}"
        else:
            if extracted.subdomain:
                final_domain = f"{extracted.subdomain}.{base_domain}"
            else:
                final_domain = base_domain

        # FIX 1: Write shared dict under lock
        with self._domains_lock:
            if final_domain not in self.captured_domains:
                self.captured_domains[final_domain] = request.resource_type
                self.write_log(f"[Captured] {final_domain}  <--  ({request.resource_type})")

    # ── Cleanup & save ───────────────────────────────────────────────────────

    def _trigger_cleanup(self):
        """Called from the background thread; schedules save_and_cleanup on the
        main thread via after(). The _cleanup_called flag prevents a second
        call if the browser was closed manually and stop_session() also fires."""
        # FIX 2: only allow one cleanup run
        if self._cleanup_called:
            return
        self._cleanup_called = True
        # FIX 6: schedule all GUI updates on the main thread
        self.after(0, self.save_and_cleanup)

    def format_for_product(self, domain_data, product_type):
        formatted_rows = []
        for domain in sorted(domain_data.keys()):
            res_type = domain_data[domain]

            if product_type == "Standard":
                formatted_rows.append([domain, res_type])
            elif product_type == "GoGuardian":
                formatted_rows.append(["allow", domain])
            else:
                formatted_rows.append([domain])

        headers = []
        if product_type == "Standard":
            headers = ["Domain", "Source"]
        elif product_type == "GoGuardian":
            headers = ["action", "url"]
        # All other products (Deledao, Lightspeed, Securly, Blocksi): no header row

        return headers, formatted_rows

    def save_and_cleanup(self):
        """Runs on the main thread (scheduled via after()). Safe to touch GUI widgets."""
        # FIX 1: snapshot domain data under lock before iterating
        with self._domains_lock:
            domain_snapshot = dict(self.captured_domains)

        if domain_snapshot and self.output_folder:
            product = self.export_format_var.get()
            timestamp = time.strftime("%d%m%y-%H%M")
            filename = f"whitelist_{product}_{timestamp}.csv"
            filepath = os.path.join(self.output_folder, filename)

            headers, rows = self.format_for_product(domain_snapshot, product)

            # Per-product row limit warnings
            if product == "Lightspeed" and len(rows) > 500:
                self.write_log(f"[Warning] Lightspeed limit is 500 rows — captured {len(rows)}. Truncating to 500.")
                rows = rows[:500]
            elif product == "GoGuardian" and len(rows) > 10000:
                self.write_log(f"[Warning] GoGuardian limit is 10,000 rows — captured {len(rows)}. Truncating to 10,000.")
                rows = rows[:10000]

            try:
                with open(filepath, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    if headers:
                        writer.writerow(headers)
                    writer.writerows(rows)
                self.write_log(f"\n[Success] Saved {len(domain_snapshot)} domains to {filename}")
            except Exception as e:
                self.write_log(f"[Error] Failed to save CSV: {e}")

        # FIX 6: GUI widget updates happen here, on the main thread
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.mode_selector.configure(state="normal")
        self.write_log("=== SESSION ENDED ===")


if __name__ == "__main__":
    app = NetworkWhitelisterApp()
    app.mainloop()
