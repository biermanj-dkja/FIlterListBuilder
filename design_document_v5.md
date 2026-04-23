# Design Document: Dynamic Whitelist Generator (v5.0)

---

## 1. High-Level Concept

A desktop utility that acts as a network "sniffer" during web sessions. It identifies every domain required for a website to function — including CDNs, authentication providers, redirects, and nested iframes — filters out known advertisers and trackers, and exports a clean, product-formatted CSV for firewall whitelisting.

The tool supports two operational modes: a **Manual Mode** for interactive browsing sessions and a **Batch Mode** for automated, headless processing of a URL list. Output files are named with a timestamp and the target product name, and saved by default to the user's Downloads folder.

---

## 2. Core Logic & Technical Requirements

### A. Deep Interception (Playwright)

- **Context-level monitoring:** Use `browser_context.on('request', ...)` instead of page-level monitoring. This ensures capture of requests from iframes, service workers, and background processes such as embedded video players or OAuth popups.
- **Data capture:** For every request, extract the full URL and the resource type (e.g., `document`, `script`, `xhr`).
- **Thread safety:** All shared state (`captured_domains`, `easylist_domains`) must be protected by a threading lock, as the Playwright request callback fires from a background thread.

### B. Domain Processing Strategy

- **Library:** Use `tldextract` to accurately separate subdomains from root domains (correctly handles multi-part TLDs such as `bbc.co.uk`).
- **Wildcard toggle:**
  - ON (default): Transform `api.services.google.com` → `*.google.com`
  - OFF (strict): Preserve the exact subdomain: `api.services.google.com`
- **Deduplication:** Maintain a running set of unique final-form domains to prevent repeats in the export.
- **Blocklist matching:** Before deduplicating, check the captured hostname and all of its subdomain variants against the blocklist. For example, for `ad.tracker.google.com`, check `ad.tracker.google.com`, `tracker.google.com`, and `google.com`. If any variant matches, discard the domain entirely.

### C. Filtering (Blocklist Integration)

- **Default source:** [StevenBlack Hosts](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts) — a gold-standard, domain-level hosts file combining ads and tracking domains.
- **Local file option:** User can supply a local `.txt` file in Hosts format, EasyList/AdGuard format, or plain-domain-per-line format.
- **No filtering option:** User can disable the blocklist entirely.
- **Caching:** The downloaded blocklist is cached locally and reused for 4 hours before a fresh download is triggered. The cache is stored at `~/.cache/network-whitelister/blocklist_cache.txt` (cross-platform, stable, writable).
- **Parsing:** The parser handles three formats robustly:
  1. Hosts file format: `0.0.0.0 domain.com` or `127.0.0.1 domain.com`
  2. EasyList / AdGuard format: `||domain.com^`
  3. Plain domain format: `domain.com`

---

## 3. Operational Modes

| Mode | Trigger | Browser Behavior |
|---|---|---|
| **Manual Mode** | "Start Session" button | **Headed.** Opens a visible browser. The user navigates and interacts manually. Recording continues until the user clicks "Stop & Save." |
| **Batch Mode** | "Start Session" button (with CSV selected) | **Headless.** Reads a CSV with a `url` column, navigates to each URL in sequence, waits 3 seconds for background traffic to settle, then moves to the next. |
| **Scraper Mode** | "Start Session" button (with URL entered) | **Headless.** Loads a single URL, extracts all `href` links from anchor tags in the DOM, and saves a `Domain` + `Link` CSV. Does not capture network traffic. Optional blocklist filtering available via toggle. |

> **Note:** Batch mode login automation (auto-filling `username`/`password` fields from the CSV) is a planned future feature. The CSV may include `username` and `password` columns for forward-compatibility, but they are not currently consumed.

---

## 4. Output & Export

### Scraper Mode Output

Scraper Mode produces a separate CSV file independent of the export format selector (which applies only to traffic capture modes). The file is always named:

```
scraped_links_{DDMMYY-HHMM}.csv
```

It contains two columns with a header row:

| Column | Content |
|---|---|
| `Domain` | The hostname of the linked URL (e.g., `www.example.com`) |
| `Link` | The full resolved href (e.g., `https://www.example.com/about`) |

Links are included as-is from the DOM — no wildcard processing is applied. The following link types are excluded automatically: `javascript:` pseudo-links, `mailto:` links, and any href with no parseable hostname.

If the "Filter ad/tracking domains" toggle is ON, the same blocklist logic used in traffic capture is applied — the blocklist is downloaded/cached on demand if not already loaded.

---

### File Naming

Output files are named using the pattern:

```
whitelist_{Product}_{DDMMYY-HHMM}.csv
```

For example: `whitelist_Securly_270325-1430.csv`

### Default Save Location

The output folder defaults to the user's Downloads directory (`~/Downloads`). The user can override this with a folder picker in the UI. The selection persists for the duration of the session.

### Product Export Formats

The user selects one target product per session. The output CSV is formatted to be directly importable into that product's admin console.

| Product | Header Row | Columns | Notes |
|---|---|---|---|
| **Standard** | `Domain`, `Source` | `domain`, `resource_type` | General-purpose. Includes resource type in second column. |
| **GoGuardian** | `action`, `url` | `action` = `allow`, `url` = domain | Verified format. Domain written as captured (no `http://` prefix needed). Max 10,000 rules, 3 MB file, 255 chars per URL. Wildcard rules are supported under `url`. Optional third column `type` for YouTube video entries — not used by this tool. |
| **Securly** | *(pending verification)* | *(pending)* | Format not yet confirmed — needs vendor docs or sample file. |
| **Blocksi** | *(pending verification)* | *(pending)* | Format not yet confirmed — needs vendor docs or sample file. |
| **Lightspeed** | None | Single domain column | Verified format. No header row. One URL per row. Maximum 500 rows — tool will warn and truncate if exceeded. Auto-matches all subdomains, so wildcard mode is forced OFF when selected (same behaviour as Deledao). |
| **Deledao** | None | Single domain column | Verified format. No header row. One domain per line. Wildcard mode is forced OFF when Deledao is selected — Deledao auto-matches all subdomains, making wildcards unnecessary. |

> **To do:** Obtain vendor-confirmed format specs for Securly and Blocksi. All other formats are verified.

### GoGuardian Format Detail

GoGuardian's bulk import requires exactly two columns with headers:

```
action,url
allow,*.google.com
allow,*.googleapis.com
allow,*.gstatic.com
```

Key constraints to enforce at export time:
- Maximum **10,000 rows** — warn the user and truncate if the captured domain count exceeds this.
- Maximum **255 characters** per URL — skip any domain exceeding this limit and log a warning.
- Maximum **3 MB** file size — warn if the output file approaches this limit.
- The `action` column is always `allow` for this tool's use case.
- The optional `type` column (for YouTube video entries) is omitted.
- Domain format is flexible: `google.com` and `http://www.google.com` are treated identically by GoGuardian, so domains are written as captured without added prefixes.

### Deledao Format Detail

Deledao uses automatic subdomain matching, which means the domain format for export is simpler than other products — no wildcards are needed or recommended.

**Matching behavior (from vendor documentation):**
- `example.com` automatically matches every page in the domain, including `www.example.com` and `videos.example.com`. This is the correct form to export.
- `www.example.com` matches only pages on that specific subdomain — too narrow for this tool's use case.
- Wildcards (`*`) are supported but behave non-standardly depending on position and adjacent characters, and are explicitly described as "usually not necessary." This tool should **never output wildcard-prefixed domains** for Deledao.

**Domain transformation rule for Deledao export:**
Selecting Deledao automatically disables wildcard mode for the session. Because Deledao auto-matches all subdomains, exact subdomain output (wildcard OFF) is sufficient — `videos.example.com` is as complete as `*.example.com` for their purposes. This avoids any need for a special re-parsing step at export time.

UI behavior when Deledao is selected:
- Wildcard toggle is forced OFF and disabled (greyed out).
- A small info label appears near the toggle: *"Disabled — Deledao matches subdomains automatically."*
- The previous wildcard state is stored in memory.
- When the user switches to any other product, the toggle is re-enabled and restored to its previous state.

**CSV structure — confirmed:**
No header row. Single column. One domain per line. Example output:

```
videos.example.com
api.googleapis.com
cdn.cloudfront.net
```

**Still needed from Deledao:** Nothing — format is fully confirmed.

### Lightspeed Format Detail

Lightspeed's Custom Allow List import uses the simplest format of all confirmed products:

```
*.google.com
*.googleapis.com
*.gstatic.com
```

Key constraints to enforce at export time:
- Maximum **500 rows** — the tightest limit of any supported product. Tool warns and truncates if exceeded.
- No header row.
- Single URL column.
- **Wildcard mode is forced OFF** when Lightspeed is selected, identical to Deledao behaviour. The previous wildcard state is stored and restored when the user switches to another product. The UI toggle is greyed out with the label: *"Disabled — this product matches subdomains automatically."*
- No special domain transformation required — exact subdomains are written as captured.

---

## 5. GUI Layout (CustomTkinter)

The UI is a modern, dark-themed desktop window divided into two panels.

### Left Panel — Configuration (Scrollable)

The left panel is a `CTkScrollableFrame` to ensure all controls remain accessible on smaller screens or at reduced window sizes.

| Control | Type | Description |
|---|---|---|
| Mode selector | Segmented button | Switches between **Manual Mode** and **Batch Mode** |
| URL entry *(Manual only)* | Text entry | Starting URL for the browser session |
| URL entry *(Scraper only)* | Text entry | URL of the page to scrape for links |
| Filter toggle *(Scraper only)* | Toggle | Enables blocklist filtering on scraped links (off by default) |
| CSV picker *(Batch only)* | File button + label | Selects `credentials.csv` containing a `url` column |
| Wildcard switch | Toggle | Enables/disables wildcard domain formatting |
| Blocklist source | Dropdown | `Cloud Blocklist (Ads/Tracking)` / `Local File` / `None` |
| Local file picker *(Local only)* | File button + label | Appears only when "Local File" is selected; resolved on the main thread before session starts |
| Export format | Radio group | Selects target product (Standard, Securly, GoGuardian, Deledao, Blocksi, Lightspeed) |
| Output folder | Directory button + label | Defaults to `~/Downloads`; user can override |
| Start Session | Button (green) | Validates inputs and launches the backend thread |
| Stop & Save | Button (red) | Signals the backend to stop and triggers CSV export |

### Right Panel — Network Log

A scrollable, read-only `CTkTextbox` displaying real-time log output from the session, including captured domains, blocked domains, system messages, and errors. Uses monospaced font for alignment.

Sample log output:
```
=== SESSION STARTED ===
[System] Using cached Blocklist (less than 4 hours old).
[System] Loaded 142,831 ad/tracking domains into filter.
[System] Navigating to https://example.com
[Captured] *.example.com  <--  (document)
[Captured] *.cloudfront.net  <--  (script)
[Captured] *.googleapis.com  <--  (xhr)

[Success] Saved 47 domains to whitelist_Securly_270325-1430.csv
=== SESSION ENDED ===
```

---

## 6. Threading & Safety Model

The GUI must remain responsive at all times. All Playwright operations run in a daemon thread. The following rules apply:

- **GUI updates from background threads are forbidden.** All widget `.configure()` calls, log writes, and session cleanup must execute on the main thread via the queue or `self.after()`.
- **Shared state is protected by a lock.** `captured_domains` and `easylist_domains` are read and written under `threading.Lock()`.
- **`filedialog` is called only from the main thread.** Local blocklist file selection happens in the UI before the session thread is started. The resolved path is passed to the thread as a plain string.
- **Cleanup runs exactly once.** A `_cleanup_called` flag prevents `save_and_cleanup()` from being invoked twice if the user manually closes the browser and also clicks Stop.
- **Browser close is handled gracefully.** If the user closes the browser window during Manual Mode, the `page.wait_for_timeout()` call will throw. This is caught, `is_running` is set to False, and the session exits cleanly.

---

## 7. Required Python Libraries

```
playwright      # Browser automation and network interception
customtkinter   # Modern GUI framework
tldextract      # Accurate domain/suffix parsing
requests        # Fetching and caching the cloud blocklist
```

---

## 8. Planned / Out of Scope

| Feature | Status |
|---|---|
| CLI interface (run core logic without GUI) | Planned — not yet implemented |
| Batch mode login automation (auto-fill username/password) | Planned — CSV columns reserved |
| Progress bar for batch processing | Planned |
| Per-session domain count summary in log footer | Planned |
| GoGuardian export format | Verified — implemented |
| Lightspeed export format | Verified — no header, single column, 500-row limit |
| Vendor format verification for Securly and Blocksi | Needs vendor docs or sample CSV |
| Deledao wildcard toggle behavior | Confirmed — auto-disable on select, restore on deselect |
| Deledao export format | Verified — no header, single domain column |
| Bark support | Removed — no bulk upload feature |
