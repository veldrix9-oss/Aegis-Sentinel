#!/usr/bin/env python3
"""
Aegis Sentinel – Billion-Signature Edition (Termux)
- Bloom filter for billions of malware hashes (probabilistic)
- SQLite exact-match backup
- AI heuristic scanner combined
"""
import os, sys, math, hashlib, sqlite3, time, re, logging, mmap
from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup
import mmh3
from bitarray import bitarray

# ================== CONFIG ==================
LOG_FILE = "aegis_scan.log"
DOWNLOAD_DIR = "aegis_downloads"
MAX_CRAWL_DEPTH = 1
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
USER_AGENT = "AegisSentinel/1.0"

# Bloom filter file (will be created/used)
BLOOM_FILENAME = "bloom_malware.bin"
# Expected number of signatures (adjust as you load more)
EXPECTED_ELEMENTS = 100_000_000   # 100 million
# False positive probability (0.1% = 0.001)
FALSE_POSITIVE_RATE = 0.001

# SQLite database for exact hashes
DB_FILENAME = "exact_malware.db"

SUSPICIOUS_PATTERNS = [
    r'eval\(.*base64_decode',
    r'exec\(',
    r'powershell -enc',
    r'<script>.*document.write\(',
    r'rm -rf',
]

# ================== LOGGING ==================
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
def log_result(msg, level="info"):
    if level == "warning":
        logging.warning(msg)
    else:
        logging.info(msg)
    print(msg)

# ================== BLOOM FILTER (MMAP) ==================
class BloomFilter:
    def __init__(self, filename, expected_n, p):
        self.filename = filename
        # Calculate optimal size and number of hash functions
        self.size = self._optimal_size(expected_n, p)
        self.hash_count = self._optimal_hash_count(self.size, expected_n)
        # Calculate size in bytes
        self.byte_size = (self.size + 7) // 8
        # Open or create memory-mapped file
        if not os.path.exists(filename):
            # Create new file filled with zeros
            with open(filename, 'wb') as f:
                f.write(b'\x00' * self.byte_size)
        self.file = open(filename, 'r+b')
        # Memory-map the file
        self.mmap = mmap.mmap(self.file.fileno(), 0)
        self.bits = bitarray(endian='little')
        self.bits.frombytes(self.mmap)

    def _optimal_size(self, n, p):
        """m = -n*ln(p) / (ln(2)^2)"""
        return int(-n * math.log(p) / (math.log(2) ** 2))

    def _optimal_hash_count(self, m, n):
        """k = (m/n) * ln(2)"""
        return int((m / n) * math.log(2))

    def _hashes(self, item):
        """Generate k hash values using double hashing technique."""
        if isinstance(item, str):
            item = item.encode('utf-8')
        h1 = mmh3.hash(item, seed=42)
        h2 = mmh3.hash(item, seed=84)
        for i in range(self.hash_count):
            yield (h1 + i * h2) % self.size

    def add(self, item):
        for pos in self._hashes(item):
            self.bits[pos] = 1

    def contains(self, item):
        for pos in self._hashes(item):
            if not self.bits[pos]:
                return False
        return True

    def save(self):
        """Write back the bitarray to the memory-mapped file and sync."""
        self.bits.tofile(self.file)
        self.file.flush()
        self.mmap.flush()

    def close(self):
        self.save()
        self.mmap.close()
        self.file.close()

# ================== SQLite EXACT LOOKUP ==================
def init_db():
    conn = sqlite3.connect(DB_FILENAME)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE IF NOT EXISTS malware_hashes (hash TEXT PRIMARY KEY, type TEXT)")
    conn.commit()
    return conn

def add_exact_hash(conn, h, h_type="md5"):
    try:
        conn.execute("INSERT OR IGNORE INTO malware_hashes (hash, type) VALUES (?, ?)", (h, h_type))
        conn.commit()
    except:
        pass

def is_exact_match(conn, h):
    cur = conn.execute("SELECT 1 FROM malware_hashes WHERE hash=?", (h,))
    return cur.fetchone() is not None

# ================== AI SCANNER (UPGRADED) ==================
def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

def scan_file(filepath, bloom, db_conn):
    """Returns (verdict, details) using Bloom + SQLite + heuristics."""
    if not os.path.isfile(filepath):
        return "ERROR", "File not found."
    file_size = os.path.getsize(filepath)
    if file_size > MAX_FILE_SIZE:
        return "SKIP", f"Too large ({file_size} bytes)."

    try:
        with open(filepath, "rb") as f:
            content = f.read()
    except Exception as e:
        return "ERROR", str(e)

    md5_hash = hashlib.md5(content).hexdigest()
    sha1_hash = hashlib.sha1(content).hexdigest()
    # We'll use SHA-1 for Bloom/SQLite (could use MD5 too)
    check_hash = sha1_hash

    # 1. Bloom filter check (billions-scale)
    if bloom.contains(check_hash):
        # Possibly known malware -> confirm with SQLite
        if is_exact_match(db_conn, check_hash):
            return "MALICIOUS", f"Exact signature match (SHA1: {check_hash})"
        else:
            # False positive of Bloom, still flag as suspicious because rare
            verdict = "SUSPICIOUS"
            details = "Bloom filter hit (unconfirmed exact match, possible new variant)"
    else:
        verdict = "CLEAN"
        details = ""

    # 2. Entropy check
    entropy = calculate_entropy(content)
    high_entropy = entropy > 7.5

    # 3. Suspicious patterns
    try:
        text_content = content.decode('utf-8', errors='ignore')
    except:
        text_content = ""
    matched_patterns = []
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, text_content, re.IGNORECASE):
            matched_patterns.append(pattern)

    reasons = []
    if details:
        reasons.append(details)
    if matched_patterns:
        reasons.append(f"suspicious patterns: {matched_patterns}")
        if verdict == "CLEAN":
            verdict = "SUSPICIOUS"
    if high_entropy:
        reasons.append(f"high entropy ({entropy:.2f})")
        if verdict == "CLEAN":
            verdict = "SUSPICIOUS"

    if not reasons:
        reasons.append("no threats detected")
    final_details = "; ".join(reasons)
    return verdict, final_details

# ================== SPIDER / CRAWLER (unchanged core) ==================
def download_file(url, save_dir):
    try:
        local_name = url.split('/')[-1].split('?')[0] or "download.bin"
        safe_name = re.sub(r'[^\w\-_\.]', '_', local_name)
        full_path = os.path.join(save_dir, safe_name)
        counter = 1
        while os.path.exists(full_path):
            name, ext = os.path.splitext(safe_name)
            full_path = os.path.join(save_dir, f"{name}_{counter}{ext}")
            counter += 1
        r = requests.get(url, headers={'User-Agent': USER_AGENT}, stream=True, timeout=10)
        if r.status_code == 200:
            with open(full_path, 'wb') as f:
                for chunk in r.iter_content(1024):
                    f.write(chunk)
            return full_path
    except Exception as e:
        log_result(f"Download error {url}: {e}", "warning")
    return None

def crawl_and_scan(start_url, bloom, db_conn):
    visited = set()
    downloaded = []
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    log_result(f"[*] Crawling {start_url}")
    try:
        resp = requests.get(start_url, headers={'User-Agent': USER_AGENT}, timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')
    except Exception as e:
        log_result(f"[-] Cannot fetch start URL: {e}")
        return

    links = []
    for tag in soup.find_all(['a','link','script','img','source']):
        href = tag.get('href') or tag.get('src')
        if href:
            full_url = urljoin(start_url, href)
            if full_url not in visited and full_url.startswith('http'):
                visited.add(full_url)
                links.append(full_url)

    file_exts = ('.pdf','.apk','.exe','.zip','.rar','.doc','.docx','.xls','.xlsx','.py','.sh','.js')
    file_links = [l for l in links if any(l.lower().endswith(ext) for ext in file_exts)]
    log_result(f"[+] Found {len(file_links)} downloadable files.")
    for link in file_links:
        log_result(f"  Downloading: {link}")
        local = download_file(link, DOWNLOAD_DIR)
        if local:
            downloaded.append(local)

    log_result("\n========== SCAN RESULTS ==========")
    for file in downloaded:
        verdict, details = scan_file(file, bloom, db_conn)
        log_result(f"[{verdict}] {file} -> {details}")
        if verdict in ("MALICIOUS","SUSPICIOUS"):
            log_result(f"  ⚠️  QUARANTINE SUGGESTED", "warning")
    log_result(f"\n[*] Files saved in {DOWNLOAD_DIR}/")

# ================== LOAD SIGNATURES ==================
def load_signatures_file(bloom, db_conn, sig_file):
    """Read a file (one hash per line) and add to Bloom + SQLite."""
    count = 0
    with open(sig_file, 'r') as f:
        for line in f:
            h = line.strip()
            if h and not h.startswith('#'):
                bloom.add(h)
                add_exact_hash(db_conn, h)
                count += 1
                if count % 100000 == 0:
                    log_result(f"  Loaded {count} signatures...")
    bloom.save()
    db_conn.commit()
    log_result(f"[+] Total {count} signatures loaded into Bloom filter and database.")

# ================== CLI ==================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Aegis Billion-Line Sentinel")
        print("Usage:")
        print("  Load signatures:   python aegis_billion.py --load /path/to/hash_list.txt")
        print("  Scan local file:   python aegis_billion.py --file /path/to/file")
        print("  Crawl & scan:      python aegis_billion.py --crawl https://example.com")
        sys.exit(1)

    action = sys.argv[1]

    # Initialize Bloom and DB
    bloom = BloomFilter(BLOOM_FILENAME, EXPECTED_ELEMENTS, FALSE_POSITIVE_RATE)
    db_conn = init_db()

    if action == "--load" and len(sys.argv) == 3:
        sig_file = sys.argv[2]
        if not os.path.isfile(sig_file):
            print("Error: Hash file not found.")
            sys.exit(1)
        print(f"Loading signatures from {sig_file}...")
        load_signatures_file(bloom, db_conn, sig_file)
        print("Done. System now contains billions of security lines (if you provide that many).")

    elif action == "--file" and len(sys.argv) == 3:
        filepath = sys.argv[2]
        verdict, details = scan_file(filepath, bloom, db_conn)
        log_result(f"\nScan result: [{verdict}] {details}")
        print(f"Verdict: {verdict}")

    elif action == "--crawl" and len(sys.argv) == 3:
        url = sys.argv[2]
        crawl_and_scan(url, bloom, db_conn)

    else:
        print("Invalid arguments.")

    bloom.close()
    db_conn.close()
