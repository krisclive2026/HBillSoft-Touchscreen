import webview
import os
import sys
import json
import uuid
import hashlib
import platform
import datetime
import base64
import socket
import struct
import time
import sqlite3

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

try:
    from openpyxl import load_workbook, Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
    _OPENPYXL_OK = True
except ImportError:
    _OPENPYXL_OK = False

# ─── paths ────────────────────────────────────────────────────────────────────
def resource_path(filename):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, filename)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)

# ── Hidden data folder (sits next to the app, invisible in file explorer) ──────
_APP_DIR     = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR    = os.path.join(_APP_DIR, '.hbillsoft')
os.makedirs(_DATA_DIR, exist_ok=True)

# On Windows, mark the folder as hidden via attrib
if platform.system() == 'Windows':
    try:
        import subprocess
        subprocess.call(['attrib', '+H', _DATA_DIR], shell=False)
    except Exception:
        pass

def data_path(filename):
    """Resolve a data file into the hidden .hbillsoft folder."""
    return os.path.join(_DATA_DIR, filename)

CONFIG_FILE    = data_path('config.json')
LICENSE_FILE   = data_path('license.dat')
LASTRUN_FILE   = data_path('lastrun.dat')   # stores last-seen date (hidden from user)
EXCEL_DB_FILE  = data_path('sales_data.xlsx')  # auto-saved sales database
DB_FILE        = data_path('sales_data.db')    # SQLite database

# ─── RSA public key (vendor embeds this; private key stays with vendor) ───────
# NOTE: When you generate a new key pair in keygen_gui.py (tkinter),
#       replace the block below with the new public key shown in that dialog.
PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8N47o0fqzoqxp/bYRokm
sNyT15U7zOc5v/dK7d18ebiblOpTnEpAPEqwg4id/DeAEJyE+oizP8VO2hE21GOo
qTayv6/K9nWOsz17fgzEIpqAAwN8tmeNFrnfOb6UDJ+s4UZPuE3Y8E8hxgTIZWfZ
FA97+tw55p05FwXwxunnQXhGNMPFJppz4iDk9hnZSzIPagj53PMjg/VFcH21I2Yz
8Ey5UWU/P25KnknLWNhwZ3xHrIwJcf29YFxeIE5sEfK8F+4SSx3Te7cI/UwZNWqS
xcMjdssJaEu69EqNbQbYti3SmSAfyNQh1P6VHKVI3jGhLRdvEY7Ml7JWWlfHvD5o
swIDAQAB
-----END PUBLIC KEY-----"""

# ─── Clock tamper detection ───────────────────────────────────────────────────

# Max allowed drift between system clock and NTP (seconds)
NTP_DRIFT_TOLERANCE = 86400          # 1 day — generous for offline use
# NTP servers to try (in order)
NTP_SERVERS = [
    'time.cloudflare.com',
    'time.google.com',
    'pool.ntp.org',
    'time.windows.com',
]

def _get_ntp_time() -> datetime.date | None:
    """
    Query NTP servers for the real current time.
    Returns a date if reachable, None if all servers fail (offline).
    Uses raw UDP — no external libraries needed.
    """
    NTP_DELTA = 2208988800  # seconds between 1900-01-01 and 1970-01-01
    for server in NTP_SERVERS:
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.settimeout(3)
            data = b'\x1b' + 47 * b'\0'
            client.sendto(data, (server, 123))
            response, _ = client.recvfrom(1024)
            client.close()
            # Transmit timestamp is at bytes 40-47
            tx_timestamp = struct.unpack('!I', response[40:44])[0]
            ntp_epoch    = tx_timestamp - NTP_DELTA
            return datetime.date.fromtimestamp(ntp_epoch)
        except Exception:
            continue
    return None  # all servers unreachable (offline)


def _load_last_run_date() -> datetime.date | None:
    """Load the last-seen date stored on disk (obfuscated, not plain text)."""
    try:
        with open(LASTRUN_FILE, 'r') as f:
            raw = f.read().strip()
        # Decode: base64 → reverse → date string
        decoded = base64.b64decode(raw.encode()).decode()[::-1]
        return datetime.date.fromisoformat(decoded)
    except Exception:
        return None


def _save_last_run_date(date: datetime.date):
    """Persist today's date to disk (lightly obfuscated)."""
    try:
        # Obfuscate: reverse string → base64 (not encryption, just not plain-text)
        raw     = date.isoformat()[::-1]
        encoded = base64.b64encode(raw.encode()).decode()
        with open(LASTRUN_FILE, 'w') as f:
            f.write(encoded)
    except Exception:
        pass  # read-only filesystem edge case — don't crash


def detect_clock_tampering(issued_date_str: str) -> dict:
    """
    Run all three clock-tamper checks.
    Returns:
      tampered (bool)  — True if tampering detected
      reason   (str)   — human-readable reason if tampered
      source   (str)   — 'ntp' | 'lastrun' | 'issued' | 'ok'
    """
    today = datetime.date.today()

    # ── Layer 1: Issued-date check (always offline) ───────────────────────────
    # If today is BEFORE the issue date, the clock was clearly rolled back.
    try:
        issued = datetime.date.fromisoformat(issued_date_str)
        if today < issued:
            return {
                'tampered': True,
                'reason':   'System date is before the license issue date. Please correct your system clock.',
                'source':   'issued'
            }
    except Exception:
        pass

    # ── Layer 2: Last-run date check (always offline) ─────────────────────────
    # If today is BEFORE the last time the app ran, the clock was rolled back.
    last_run = _load_last_run_date()
    if last_run and today < last_run:
        return {
            'tampered': True,
            'reason':   'System date appears to have been set back. Please correct your system clock.',
            'source':   'lastrun'
        }

    # ── Layer 3: NTP check (online, best-effort) ──────────────────────────────
    # If we can reach a time server, compare against system clock.
    ntp_date = _get_ntp_time()
    if ntp_date is not None:
        drift_days = abs((today - ntp_date).days)
        if drift_days > 1:   # more than 1 day off
            return {
                'tampered': True,
                'reason':   f'System clock is {drift_days} day(s) off from internet time. Please correct your system clock.',
                'source':   'ntp'
            }

    # All checks passed — update last-run date
    _save_last_run_date(today)
    return {'tampered': False, 'reason': '', 'source': 'ok'}


# ─── System Code (machine fingerprint) ────────────────────────────────────────
def get_system_code() -> str:
    """Build a stable machine fingerprint from hardware identifiers."""
    parts = []

    try:
        parts.append(str(uuid.getnode()))
    except Exception:
        pass
    try:
        parts.append(platform.node())
    except Exception:
        pass
    try:
        parts.append(platform.machine())
    except Exception:
        pass
    try:
        parts.append(platform.processor())
    except Exception:
        pass

    for path in ['/etc/machine-id', '/var/lib/dbus/machine-id']:
        try:
            with open(path) as f:
                parts.append(f.read().strip())
            break
        except Exception:
            pass
    if platform.system() == 'Windows':
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r'SOFTWARE\Microsoft\Cryptography')
            val, _ = winreg.QueryValueEx(key, 'MachineGuid')
            parts.append(val)
        except Exception:
            pass

    raw    = '|'.join(parts)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    d      = digest[:16].upper()
    return '-'.join([d[i:i+4] for i in range(0, 16, 4)])


# ─── License validation ───────────────────────────────────────────────────────
def _load_public_key():
    return serialization.load_pem_public_key(PUBLIC_KEY_PEM, backend=default_backend())

def verify_license_key(license_key: str, system_code: str) -> dict:
    """
    Returns dict with keys:
      valid (bool), expired (bool), expiry (str), customer (str),
      issued (str), days_left (int), error (str), clock_tampered (bool)
    """
    try:
        # Sanitize
        clean_key = license_key.strip()
        clean_key = clean_key.replace('\r', '').replace('\n', '').replace(' ', '')
        clean_key = clean_key.lstrip('\ufeff')

        raw         = base64.b64decode(clean_key.encode())
        bundle      = json.loads(raw)
        payload_b64 = bundle['payload']
        sig_b64     = bundle['signature']

        payload_bytes = base64.b64decode(payload_b64)
        sig_bytes     = base64.b64decode(sig_b64)

        # 1. Verify RSA signature
        pub_key = _load_public_key()
        pub_key.verify(sig_bytes, payload_bytes, padding.PKCS1v15(), hashes.SHA256())

        # 2. Decode payload
        data = json.loads(payload_bytes)

        # 3. Check system code binding
        if data.get('system_code', '').upper() != system_code.upper():
            return {'valid': False, 'error': 'License is not valid for this machine.', 'clock_tampered': False}

        # 4. Check product
        if data.get('product', '') != 'HBILLSOFT':
            return {'valid': False, 'error': 'Invalid product in license.', 'clock_tampered': False}

        # 5. Clock tamper detection (all three layers)
        issued_str  = data.get('issued', datetime.date.today().isoformat())
        tamper_info = detect_clock_tampering(issued_str)
        if tamper_info['tampered']:
            return {
                'valid':          False,
                'expired':        False,
                'clock_tampered': True,
                'error':          tamper_info['reason'],
                'expiry':         data.get('expiry', ''),
                'customer':       data.get('customer', ''),
                'issued':         issued_str,
                'days_left':      0,
            }

        # 6. Check expiry
        expiry_date = datetime.date.fromisoformat(data['expiry'])
        today       = datetime.date.today()
        expired     = today > expiry_date
        days_left   = (expiry_date - today).days if not expired else 0

        return {
            'valid':          True,
            'expired':        expired,
            'expiry':         data['expiry'],
            'customer':       data.get('customer', ''),
            'issued':         issued_str,
            'days_left':      days_left,
            'clock_tampered': False,
            'error':          ''
        }
    except Exception as e:
        return {'valid': False, 'error': f'License verification failed: {e}', 'clock_tampered': False}


def load_saved_license() -> str:
    try:
        with open(LICENSE_FILE, 'r') as f:
            return f.read().strip()
    except Exception:
        return ''

def save_license(key: str):
    with open(LICENSE_FILE, 'w') as f:
        f.write(key.strip())

# ─── Config helpers ───────────────────────────────────────────────────────────
def load_config_from_file():
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_config_to_file(data):
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        return True
    except Exception:
        return False

# ─── SQLite Database Functions ────────────────────────────────────────────────
def init_database():
    """Initialize SQLite database with orders and items tables."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Create orders table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS orders (
                id TEXT PRIMARY KEY,
                date TEXT NOT NULL,
                subtotal REAL NOT NULL,
                discount REAL NOT NULL,
                sgst REAL NOT NULL,
                cgst REAL NOT NULL,
                total REAL NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create order_items table (links items to orders)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS order_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id TEXT NOT NULL,
                item_name TEXT NOT NULL,
                item_id TEXT,
                quantity INTEGER NOT NULL,
                price REAL NOT NULL,
                item_total REAL NOT NULL,
                FOREIGN KEY(order_id) REFERENCES orders(id)
            )
        ''')
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Database init error: {e}")
        return False

def save_order_to_db(order: dict) -> dict:
    """Save an order and its items to SQLite database."""
    try:
        init_database()
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        order_id = order.get('id', str(uuid.uuid4()))
        date = order.get('date', datetime.datetime.now().isoformat())
        subtotal = float(order.get('subtotal', 0))
        discount = float(order.get('discount', 0))
        sgst = float(order.get('sgst', 0))
        cgst = float(order.get('cgst', 0))
        total = float(order.get('total', 0))
        
        # Save order
        cursor.execute('''
            INSERT OR REPLACE INTO orders 
            (id, date, subtotal, discount, sgst, cgst, total)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (order_id, date, subtotal, discount, sgst, cgst, total))
        
        # Save order items
        for item in order.get('items', []):
            cursor.execute('''
                INSERT INTO order_items 
                (order_id, item_name, item_id, quantity, price, item_total)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                order_id,
                item.get('name', ''),
                item.get('id', ''),
                item.get('qty', 1),
                item.get('price', 0),
                float(item.get('qty', 1)) * float(item.get('price', 0))
            ))
        
        conn.commit()
        conn.close()
        return {'ok': True, 'order_id': order_id}
    except Exception as e:
        print(f"Error saving order to DB: {e}")
        return {'ok': False, 'error': str(e)}

def load_orders_from_db() -> dict:
    """Load all orders from SQLite database."""
    try:
        init_database()
        if not os.path.exists(DB_FILE):
            return {'ok': True, 'orders': []}
        
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get all orders
        cursor.execute('SELECT * FROM orders ORDER BY date DESC')
        orders_rows = cursor.fetchall()
        
        orders = []
        for order_row in orders_rows:
            order_id = order_row['id']
            
            # Get items for this order
            cursor.execute('''
                SELECT item_name, item_id, quantity, price, item_total 
                FROM order_items 
                WHERE order_id = ?
            ''', (order_id,))
            items_rows = cursor.fetchall()
            
            items = [
                {
                    'name': item['item_name'],
                    'id': item['item_id'],
                    'qty': item['quantity'],
                    'price': item['price'],
                    'total': item['item_total']
                }
                for item in items_rows
            ]
            
            order = {
                'id': order_row['id'],
                'date': order_row['date'],
                'items': items,
                'subtotal': order_row['subtotal'],
                'discount': order_row['discount'],
                'sgst': order_row['sgst'],
                'cgst': order_row['cgst'],
                'gst': order_row['sgst'],  # For compatibility
                'total': order_row['total']
            }
            orders.append(order)
        
        conn.close()
        return {'ok': True, 'orders': orders}
    except Exception as e:
        print(f"Error loading orders from DB: {e}")
        return {'ok': False, 'error': str(e), 'orders': []}

def get_sales_summary(from_date=None, to_date=None) -> dict:
    """
    Get sales summary with items grouped by name, quantities, and date-based filtering.
    Returns items with total quantity sold and total revenue.
    """
    try:
        init_database()
        if not os.path.exists(DB_FILE):
            return {'ok': True, 'summary': [], 'total_revenue': 0}
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Build query with optional date filtering
        query = '''
            SELECT 
                oi.item_name,
                SUM(oi.quantity) as total_qty,
                AVG(oi.price) as avg_price,
                SUM(oi.item_total) as total_revenue,
                COUNT(DISTINCT oi.order_id) as order_count
            FROM order_items oi
            JOIN orders o ON oi.order_id = o.id
        '''
        
        params = []
        if from_date or to_date:
            query += ' WHERE'
            if from_date:
                query += ' o.date >= ?'
                params.append(from_date)
            if from_date and to_date:
                query += ' AND'
            if to_date:
                query += ' o.date <= ?'
                params.append(to_date)
        
        query += ' GROUP BY oi.item_name ORDER BY total_revenue DESC'
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        summary = []
        total_revenue = 0
        for row in rows:
            item_summary = {
                'name': row[0],
                'quantity': int(row[1]),
                'avg_price': round(row[2], 2),
                'revenue': round(row[3], 2),
                'orders': int(row[4])
            }
            summary.append(item_summary)
            total_revenue += row[3]
        # Also compute total distinct orders and tax totals in the filtered range
        orders_count = None
        total_sgst = 0.0
        total_cgst = 0.0
        grand_total_including_tax = 0.0
        try:
            # Count distinct orders
            count_query = 'SELECT COUNT(DISTINCT o.id) FROM orders o'
            sum_query = 'SELECT SUM(o.sgst), SUM(o.cgst), SUM(o.total) FROM orders o'
            if from_date or to_date:
                where_parts = []
                params_count = []
                if from_date:
                    where_parts.append('o.date >= ?')
                    params_count.append(from_date)
                if to_date:
                    where_parts.append('o.date <= ?')
                    params_count.append(to_date)
                where_clause = ' WHERE ' + ' AND '.join(where_parts)
                cursor.execute(count_query + where_clause, params_count)
                orders_count = cursor.fetchone()[0]
                cursor.execute(sum_query + where_clause, params_count)
            else:
                cursor.execute(count_query)
                orders_count = cursor.fetchone()[0]
                cursor.execute(sum_query)

            sums = cursor.fetchone()
            if sums:
                total_sgst = float(sums[0] or 0)
                total_cgst = float(sums[1] or 0)
                grand_total_including_tax = float(sums[2] or 0)
        except Exception:
            orders_count = None

        conn.close()
        return {
            'ok': True,
            'summary': summary,
            'total_revenue': round(total_revenue, 2),            # item totals (pre-tax)
            'orders_count': orders_count,
            'total_sgst': round(total_sgst, 2),
            'total_cgst': round(total_cgst, 2),
            'total_gst': round(total_sgst + total_cgst, 2),
            'grand_total': round(grand_total_including_tax, 2)   # including tax
        }
    except Exception as e:
        print(f"Error getting sales summary: {e}")
        return {'ok': False, 'error': str(e), 'summary': [], 'total_revenue': 0}

# ─── pywebview API ────────────────────────────────────────────────────────────
class Api:
    def close_window(self):
        window.destroy()

    def load_config(self):
        return load_config_from_file()

    def save_config(self, data):
        return save_config_to_file(data)

    def get_session_count(self):
        return load_config_from_file().get('sessionCount', 0)

    # --- License API ---
    def get_system_code(self):
        return get_system_code()

    def activate_license(self, license_key: str):
        sc     = get_system_code()
        result = verify_license_key(license_key, sc)
        if result['valid'] and not result['expired'] and not result.get('clock_tampered'):
            save_license(license_key)
        return result

    def check_license(self):
        sc  = get_system_code()
        key = load_saved_license()
        if not key:
            return {'valid': False, 'expired': False, 'error': 'No license found.', 'system_code': sc, 'clock_tampered': False}
        result = verify_license_key(key, sc)
        result['system_code'] = sc
        return result

    def renew_license(self, new_key: str):
        """Renew/replace an expired license with a new key."""
        return self.activate_license(new_key)

    # --- Excel Sales DB ---
    def get_excel_path(self) -> str:
        """Return the path of the auto-saved sales Excel file."""
        return EXCEL_DB_FILE

    def save_order_to_excel(self, order: dict) -> dict:
        """
        After each completed order, rebuild the day-sheet in sales_data.xlsx
        using the same item-wise format as the export report.
        Each day gets its own sheet; sheets from previous days are untouched.
        Returns {'ok': True} or {'ok': False, 'error': '...'}.
        """
        if not _OPENPYXL_OK:
            return {'ok': False, 'error': 'openpyxl not installed. Run: pip install openpyxl'}

        try:
            cfg        = load_config_from_file()
            curr       = cfg.get('currency', '₹')
            restaurant = cfg.get('restaurantName', 'HBILLSOFT')

            order_dt   = datetime.datetime.fromisoformat(order.get('date', datetime.datetime.now().isoformat()))
            sheet_name = order_dt.strftime('%d-%b-%Y')   # e.g. "22-May-2026"

            # ── Pull today's aggregated data from SQLite ────────────────────
            day_start = order_dt.strftime('%Y-%m-%d') + 'T00:00:00'
            day_end   = order_dt.strftime('%Y-%m-%d') + 'T23:59:59'
            summary   = get_sales_summary(day_start, day_end)

            items       = summary.get('summary', [])      # [{name, quantity, avg_price, revenue}]
            sgst        = round(summary.get('total_sgst', 0), 2)
            cgst        = round(summary.get('total_cgst', 0), 2)
            grand_total = round(summary.get('grand_total', 0), 2)
            items_total = round(summary.get('total_revenue', 0), 2)
            discount    = round(max(items_total + sgst + cgst - grand_total, 0), 2)
            total_qty   = sum(it['quantity'] for it in items)

            # ── Style helpers ───────────────────────────────────────────────
            BLUE       = '1a3c5e'
            WHITE      = 'FFFFFF'
            LIGHT_BLUE = 'EAF2FB'
            GREEN_DARK = '1d5c2e'

            def tborder():
                s = Side(style='thin', color='BBBBBB')
                return Border(left=s, right=s, top=s, bottom=s)

            def mborder():
                s = Side(style='medium', color=BLUE)
                return Border(left=s, right=s, top=s, bottom=s)

            c_center = Alignment(horizontal='center', vertical='center')
            c_left   = Alignment(horizontal='left',   vertical='center', indent=1)
            c_right  = Alignment(horizontal='right',  vertical='center')
            money_fmt = f'"{curr}"#,##0.00'

            # ── Load or create workbook ─────────────────────────────────────
            if os.path.exists(EXCEL_DB_FILE):
                wb = load_workbook(EXCEL_DB_FILE)
            else:
                wb = Workbook()
                if 'Sheet' in wb.sheetnames:
                    del wb['Sheet']

            # Remove and recreate today's sheet so it's always fresh
            if sheet_name in wb.sheetnames:
                del wb[sheet_name]
            ws = wb.create_sheet(title=sheet_name)

            # ── Column widths ───────────────────────────────────────────────
            ws.column_dimensions['A'].width = 36
            ws.column_dimensions['B'].width = 12
            ws.column_dimensions['C'].width = 18
            ws.column_dimensions['D'].width = 18

            # ── Row 1: Restaurant name ──────────────────────────────────────
            ws.merge_cells('A1:D1')
            c = ws['A1']
            c.value     = restaurant
            c.font      = Font(bold=True, size=15, color=WHITE)
            c.fill      = PatternFill('solid', fgColor=BLUE)
            c.alignment = c_center
            ws.row_dimensions[1].height = 24

            # ── Row 2: Report title ─────────────────────────────────────────
            ws.merge_cells('A2:D2')
            c = ws['A2']
            c.value     = 'Daily Sales Report'
            c.font      = Font(bold=True, size=11, color=WHITE)
            c.fill      = PatternFill('solid', fgColor=BLUE)
            c.alignment = c_center
            ws.row_dimensions[2].height = 18

            # ── Row 3: Date ─────────────────────────────────────────────────
            ws.merge_cells('A3:D3')
            c = ws['A3']
            c.value     = f'Date: {sheet_name}'
            c.font      = Font(italic=True, size=10, color='555555')
            c.fill      = PatternFill('solid', fgColor='F0F4F8')
            c.alignment = c_center
            ws.row_dimensions[3].height = 16

            # ── Row 4: blank ────────────────────────────────────────────────
            ws.append([])
            ws.row_dimensions[4].height = 6

            # ── Row 5: Column headers ───────────────────────────────────────
            headers = ['Item Name', 'Qty Sold', f'Unit Price ({curr})', f'Amount ({curr})']
            ws.append(headers)
            for col_idx in range(1, 5):
                cell = ws.cell(row=5, column=col_idx)
                cell.font      = Font(bold=True, color=WHITE, size=10)
                cell.fill      = PatternFill('solid', fgColor=BLUE)
                cell.alignment = c_center
                cell.border    = tborder()
            ws.row_dimensions[5].height = 18

            # ── Item rows ───────────────────────────────────────────────────
            for i, item in enumerate(items):
                row_num = 6 + i
                bg = LIGHT_BLUE if i % 2 == 0 else WHITE
                fill = PatternFill('solid', fgColor=bg)
                ws.append([
                    item['name'],
                    item['quantity'],
                    round(item['avg_price'], 2),
                    round(item['revenue'], 2),
                ])
                ws.cell(row=row_num, column=1).alignment = c_left
                ws.cell(row=row_num, column=2).alignment = c_center
                ws.cell(row=row_num, column=3).alignment = c_center
                ws.cell(row=row_num, column=4).alignment = c_right
                for col_idx in range(1, 5):
                    ws.cell(row=row_num, column=col_idx).fill   = fill
                    ws.cell(row=row_num, column=col_idx).border = tborder()
                ws.cell(row=row_num, column=3).number_format = money_fmt
                ws.cell(row=row_num, column=4).number_format = money_fmt

            # ── Blank separator ─────────────────────────────────────────────
            sep = ws.max_row + 1
            ws.append([])
            ws.row_dimensions[sep].height = 8

            # ── Totals block ────────────────────────────────────────────────
            totals = [
                ('Total Items Sold',           total_qty, items_total),
                ('Discount',                   '',        discount),
                ('Subtotal (after discount)',   '',        round(items_total - discount, 2)),
                ('SGST',                       '',        sgst),
                ('CGST',                       '',        cgst),
                ('Total GST',                  '',        round(sgst + cgst, 2)),
            ]
            for label, qty, amount in totals:
                r = ws.max_row + 1
                ws.append([label, qty, '', round(float(amount), 2)])
                ws.cell(row=r, column=1).alignment = c_left
                ws.cell(row=r, column=1).font      = Font(size=10)
                ws.cell(row=r, column=2).alignment = c_center
                ws.cell(row=r, column=4).alignment = c_right
                ws.cell(row=r, column=4).number_format = money_fmt
                for col_idx in range(1, 5):
                    ws.cell(row=r, column=col_idx).fill   = PatternFill('solid', fgColor='F7F9FC')
                    ws.cell(row=r, column=col_idx).border = tborder()

            # ── Grand total row ─────────────────────────────────────────────
            ws.append([])
            gt = ws.max_row + 1
            ws.append(['GRAND TOTAL', '', '', grand_total])
            ws.merge_cells(f'A{gt}:C{gt}')
            ws.cell(row=gt, column=1).value     = 'GRAND TOTAL'
            ws.cell(row=gt, column=1).font      = Font(bold=True, size=12, color=WHITE)
            ws.cell(row=gt, column=1).fill      = PatternFill('solid', fgColor=GREEN_DARK)
            ws.cell(row=gt, column=1).alignment = c_center
            ws.cell(row=gt, column=4).value          = grand_total
            ws.cell(row=gt, column=4).font           = Font(bold=True, size=12, color=WHITE)
            ws.cell(row=gt, column=4).fill           = PatternFill('solid', fgColor=GREEN_DARK)
            ws.cell(row=gt, column=4).number_format  = money_fmt
            ws.cell(row=gt, column=4).alignment      = c_right
            for col_idx in range(1, 5):
                ws.cell(row=gt, column=col_idx).border = mborder()
            ws.row_dimensions[gt].height = 22

            wb.save(EXCEL_DB_FILE)
            return {'ok': True, 'file': EXCEL_DB_FILE, 'sheet': sheet_name}

        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def load_orders_from_excel(self) -> dict:
        """
        Load all orders from the persistent sales_data.xlsx file.
        Returns {'ok': True, 'orders': [...]} or {'ok': False, 'error': '...', 'orders': []}.
        """
        if not _OPENPYXL_OK:
            return {'ok': False, 'error': 'openpyxl not installed', 'orders': []}

        orders = []
        try:
            if not os.path.exists(EXCEL_DB_FILE):
                return {'ok': True, 'orders': []}

            wb = load_workbook(EXCEL_DB_FILE)
            
            # Load orders from all sheets (one sheet per day)
            for sheet_name in wb.sheetnames:
                try:
                    ws = wb[sheet_name]
                    # Skip non-data rows (banner, header, etc.)
                    # Data starts at row 5
                    for row_idx, row in enumerate(ws.iter_rows(min_row=5, values_only=True), start=5):
                        if not row[0] or row[0] == 'Date':  # Skip empty/header rows
                            continue
                        
                        try:
                            # Parse date and time
                            date_str = str(row[0]) if row[0] else ''
                            time_str = str(row[1]) if row[1] else '00:00 AM'
                            datetime_str = f"{date_str} {time_str}"
                            
                            # Parse datetime - try multiple formats
                            order_dt = None
                            for fmt in ['%d-%b-%Y %I:%M %p', '%Y-%m-%d %H:%M:%S', '%d-%b-%Y %H:%M:%S']:
                                try:
                                    order_dt = datetime.datetime.strptime(datetime_str, fmt)
                                    break
                                except:
                                    continue
                            
                            if not order_dt:
                                order_dt = datetime.datetime.now()
                            
                            # Parse amounts
                            subtotal = float(row[4] or 0)
                            discount = float(row[5] or 0)
                            sgst = float(row[6] or 0)
                            cgst = float(row[7] or 0)
                            total = float(row[8] or 0)
                            
                            order = {
                                'id': str(row[2]) if row[2] else '',
                                'date': order_dt.isoformat(),
                                'items': [],  # Excel doesn't store full item details, only summary
                                'subtotal': subtotal,
                                'discount': discount,
                                'sgst': sgst,
                                'cgst': cgst,
                                'gst': sgst,  # For compatibility
                                'total': total
                            }
                            orders.append(order)
                        except Exception as row_err:
                            print(f"Error parsing row {row_idx} in sheet '{sheet_name}': {row_err}")
                            continue
                except Exception as sheet_err:
                    print(f"Error reading sheet '{sheet_name}': {sheet_err}")
                    continue
            
            return {'ok': True, 'orders': orders}

        except Exception as e:
            return {'ok': False, 'error': str(e), 'orders': []}

    def save_order(self, order: dict) -> dict:
        """Save order to SQLite database."""
        return save_order_to_db(order)

    def load_orders(self) -> dict:
        """Load all orders from SQLite database."""
        return load_orders_from_db()

    def get_sales_summary_api(self, from_date=None, to_date=None) -> dict:
        """Get sales summary with items and revenue."""
        return get_sales_summary(from_date, to_date)

    def export_sales_excel(self, from_date=None, to_date=None) -> dict:
        """
        Build a clean sales report Excel file and save it to the desktop.
        Returns {'ok': True, 'file': path} or {'ok': False, 'error': '...'}.
        """
        if not _OPENPYXL_OK:
            return {'ok': False, 'error': 'openpyxl not installed. Run: pip install openpyxl'}

        try:
            cfg  = load_config_from_file()
            curr = cfg.get('currency', '₹')
            restaurant = cfg.get('restaurantName', 'HBILLSOFT')

            # ── Fetch aggregated data ───────────────────────────────────────
            summary = get_sales_summary(from_date, to_date)
            if not summary['ok']:
                return {'ok': False, 'error': summary.get('error', 'Failed to load data')}

            items       = summary.get('summary', [])      # [{name, quantity, avg_price, revenue}]
            sgst        = summary.get('total_sgst', 0)
            cgst        = summary.get('total_cgst', 0)
            grand_total = summary.get('grand_total', 0)
            items_total = summary.get('total_revenue', 0) # pre-tax subtotal
            discount    = round(items_total + sgst + cgst - grand_total, 2)
            if discount < 0:
                discount = 0

            # ── Style helpers ───────────────────────────────────────────────
            BLUE       = '1a3c5e'
            WHITE      = 'FFFFFF'
            LIGHT_BLUE = 'EAF2FB'
            YELLOW     = 'FFF9C4'
            GREEN_DARK = '1d5c2e'

            def thin_border():
                s = Side(style='thin', color='BBBBBB')
                return Border(left=s, right=s, top=s, bottom=s)

            def thick_border():
                s = Side(style='medium', color=BLUE)
                return Border(left=s, right=s, top=s, bottom=s)

            center  = Alignment(horizontal='center', vertical='center')
            left    = Alignment(horizontal='left',   vertical='center', indent=1)
            right_a = Alignment(horizontal='right',  vertical='center')

            # ── Build workbook ──────────────────────────────────────────────
            wb = Workbook()
            ws = wb.active
            ws.title = 'Sales Report'

            # Column widths: A=Item, B=Qty, C=Unit Price, D=Amount
            ws.column_dimensions['A'].width = 36
            ws.column_dimensions['B'].width = 12
            ws.column_dimensions['C'].width = 18
            ws.column_dimensions['D'].width = 18

            money_fmt = f'"{curr}"#,##0.00'

            # ── Header block (rows 1-3) ─────────────────────────────────────
            ws.merge_cells('A1:D1')
            c = ws['A1']
            c.value     = restaurant
            c.font      = Font(bold=True, size=15, color=WHITE)
            c.fill      = PatternFill('solid', fgColor=BLUE)
            c.alignment = center
            ws.row_dimensions[1].height = 24

            ws.merge_cells('A2:D2')
            c = ws['A2']
            c.value     = 'Sales Report'
            c.font      = Font(bold=True, size=11, color=WHITE)
            c.fill      = PatternFill('solid', fgColor=BLUE)
            c.alignment = center
            ws.row_dimensions[2].height = 18

            # Period label
            if from_date or to_date:
                fd = (from_date or '').split('T')[0]
                td = (to_date   or '').split('T')[0]
                period = f'Period: {fd or "Start"}  →  {td or "Today"}'
            else:
                period = f'Exported: {datetime.date.today().strftime("%d-%b-%Y")}'

            ws.merge_cells('A3:D3')
            c = ws['A3']
            c.value     = period
            c.font      = Font(italic=True, size=10, color='555555')
            c.fill      = PatternFill('solid', fgColor='F0F4F8')
            c.alignment = center
            ws.row_dimensions[3].height = 16

            ws.append([])   # row 4 blank
            ws.row_dimensions[4].height = 6

            # ── Column headers (row 5) ──────────────────────────────────────
            headers = ['Item Name', 'Qty Sold', f'Unit Price ({curr})', f'Amount ({curr})']
            ws.append(headers)
            for col_idx, _ in enumerate(headers, start=1):
                cell = ws.cell(row=5, column=col_idx)
                cell.font      = Font(bold=True, color=WHITE, size=10)
                cell.fill      = PatternFill('solid', fgColor=BLUE)
                cell.alignment = center
                cell.border    = thin_border()
            ws.row_dimensions[5].height = 18

            # ── Item rows ───────────────────────────────────────────────────
            for i, item in enumerate(items):
                row_num = 6 + i
                fill = PatternFill('solid', fgColor=LIGHT_BLUE) if i % 2 == 0 else PatternFill('solid', fgColor=WHITE)
                ws.append([
                    item['name'],
                    item['quantity'],
                    round(item['avg_price'], 2),
                    round(item['revenue'], 2),
                ])
                ws.cell(row=row_num, column=1).alignment = left
                ws.cell(row=row_num, column=2).alignment = center
                for col_idx in range(1, 5):
                    cell = ws.cell(row=row_num, column=col_idx)
                    cell.fill   = fill
                    cell.border = thin_border()
                for col_idx in [3, 4]:
                    ws.cell(row=row_num, column=col_idx).number_format = money_fmt

            # ── Blank separator ─────────────────────────────────────────────
            sep_row = 6 + len(items)
            ws.append([])
            ws.row_dimensions[sep_row].height = 8

            # ── Totals block ────────────────────────────────────────────────
            total_qty = sum(it['quantity'] for it in items)

            totals = [
                ('Total Items Sold',          total_qty,                       '',        items_total),
                ('Discount',                  '',                              '',        discount),
                ('Subtotal (after discount)', '',                              '',        round(items_total - discount, 2)),
                ('SGST',                      '',                              '',        sgst),
                ('CGST',                      '',                              '',        cgst),
                ('Total GST',                 '',                              '',        round(sgst + cgst, 2)),
            ]

            for label, qty, _, amount in totals:
                r = ws.max_row + 1
                ws.append([label, qty, '', round(amount, 2)])
                ws.cell(row=r, column=1).font      = Font(size=10)
                ws.cell(row=r, column=1).alignment = left
                ws.cell(row=r, column=2).alignment = center
                ws.cell(row=r, column=4).number_format = money_fmt
                ws.cell(row=r, column=4).alignment = right_a
                for col_idx in range(1, 5):
                    ws.cell(row=r, column=col_idx).border = thin_border()
                    ws.cell(row=r, column=col_idx).fill   = PatternFill('solid', fgColor='F7F9FC')

            # ── Grand total row ─────────────────────────────────────────────
            ws.append([])   # blank row
            gt_row = ws.max_row + 1
            ws.append(['GRAND TOTAL', '', '', round(grand_total, 2)])
            ws.merge_cells(f'A{gt_row}:C{gt_row}')
            ws.cell(row=gt_row, column=1).value     = 'GRAND TOTAL'
            ws.cell(row=gt_row, column=1).font      = Font(bold=True, size=12, color=WHITE)
            ws.cell(row=gt_row, column=1).fill      = PatternFill('solid', fgColor=GREEN_DARK)
            ws.cell(row=gt_row, column=1).alignment = center
            ws.cell(row=gt_row, column=4).value          = round(grand_total, 2)
            ws.cell(row=gt_row, column=4).font           = Font(bold=True, size=12, color=WHITE)
            ws.cell(row=gt_row, column=4).fill           = PatternFill('solid', fgColor=GREEN_DARK)
            ws.cell(row=gt_row, column=4).number_format  = money_fmt
            ws.cell(row=gt_row, column=4).alignment      = right_a
            for col_idx in range(1, 5):
                ws.cell(row=gt_row, column=col_idx).border = thick_border()
            ws.row_dimensions[gt_row].height = 22

            # ── Save to Desktop ─────────────────────────────────────────────
            today_str = datetime.date.today().strftime('%Y-%m-%d')
            desktop = os.path.join(os.path.expanduser('~'), 'Desktop')
            if not os.path.isdir(desktop):
                desktop = os.path.expanduser('~')
            out_path = os.path.join(desktop, f'HBILLSOFT_Sales_{today_str}.xlsx')

            wb.save(out_path)
            return {'ok': True, 'file': out_path}

        except Exception as e:
            return {'ok': False, 'error': str(e)}

# ─── Startup ──────────────────────────────────────────────────────────────────
api = Api()

# Initialize database
init_database()

config = load_config_from_file()
config['sessionCount'] = config.get('sessionCount', 0) + 1
save_config_to_file(config)

html_file = resource_path('RestoPOS.html')

window = webview.create_window(
    title='HBILLSOFT',
    url='file:///' + html_file.replace('\\', '/'),
    width=1280,
    height=800,
    min_size=(1024, 600),
    resizable=True,
    fullscreen=True,
    js_api=api
)

webview.start()
