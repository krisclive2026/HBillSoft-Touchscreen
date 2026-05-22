"""
HBILLSOFT License Key Generator — GUI Tool (Vendor Use Only)
Requirements: pip install cryptography
Uses only built-in tkinter — no PyQt6 needed.

Private key is loaded automatically from private_key.pem in the same folder.
No customer name required — only System Code and duration.
"""

import sys
import os
import json
import base64
import datetime
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


# ── RSA helpers ────────────────────────────────────────────────────────────────

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode()
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return priv_pem, pub_pem


def load_private_key_from_file(path: str):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())


def generate_license(system_code: str, days: int, private_pem: str) -> str:
    expiry = (datetime.date.today() + datetime.timedelta(days=days)).isoformat()
    payload = json.dumps({
        "system_code": system_code.strip().upper(),
        "customer":    "HBILLSOFT",
        "issued":      datetime.date.today().isoformat(),
        "expiry":      expiry,
        "product":     "HBILLSOFT"
    }, separators=(',', ':'), ensure_ascii=False)
    private_key = serialization.load_pem_private_key(
        private_pem.encode(), password=None, backend=default_backend()
    )
    sig = private_key.sign(payload.encode(), padding.PKCS1v15(), hashes.SHA256())
    bundle = json.dumps({
        "payload":   base64.b64encode(payload.encode()).decode(),
        "signature": base64.b64encode(sig).decode()
    }, separators=(',', ':'))
    return base64.b64encode(bundle.encode()).decode()


# ── Palette ────────────────────────────────────────────────────────────────────

BG      = "#0b0d17"
BG2     = "#12152a"
BG3     = "#1a1f3a"
CARD    = "#1e2340"
BORDER  = "#2a3060"
ACCENT  = "#00b4ff"
SUCCESS = "#00d4aa"
DANGER  = "#ff3366"
WARNING = "#ffaa00"
TEXT    = "#e8eaf6"
MUTED   = "#7b82b4"
MONO    = "Courier"

FONT_BODY  = ("Segoe UI", 10)
FONT_LABEL = ("Segoe UI", 9)
FONT_MONO  = (MONO, 10)
FONT_TITLE = ("Segoe UI", 16, "bold")
FONT_BADGE = ("Segoe UI", 8, "bold")
FONT_BTN   = ("Segoe UI", 10, "bold")
FONT_SMALL = ("Segoe UI", 8)

# Project folder = folder where this script lives
PROJECT_DIR  = Path(__file__).parent
PRIVATE_KEY_PATH = PROJECT_DIR / "private_key.pem"
PUBLIC_KEY_PATH  = PROJECT_DIR / "public_key.pem"


# ── Toast ──────────────────────────────────────────────────────────────────────

class Toast:
    def __init__(self, parent: tk.Widget, text: str, kind: str = "success"):
        color = SUCCESS if kind == "success" else DANGER if kind == "error" else WARNING
        bg    = "#0d2b26" if kind == "success" else "#2b0d1a" if kind == "error" else "#2b2000"
        self._lbl = tk.Label(
            parent, text=text,
            bg=bg, fg=color, font=FONT_LABEL,
            relief="flat", padx=14, pady=8, bd=0
        )
        self._lbl.place(relx=0.5, rely=0.96, anchor="s")
        self._lbl.lift()
        parent.after(2800, self._destroy)

    def _destroy(self):
        try:
            self._lbl.destroy()
        except Exception:
            pass


# ── Main Window ────────────────────────────────────────────────────────────────

class KeygenWindow:
    def __init__(self, root: tk.Tk):
        self.root        = root
        self.private_pem: str | None = None

        self.expiry_options = [
            ("3 Months", 92),
            ("6 Months", 183),
            ("1 Year",   365),
            ("2 Years",  730),
        ]

        self._setup_window()
        self._build_ui()
        self._autoload_key()   # silently load key on startup

    # ── Window ────────────────────────────────────────────────────────────────

    def _setup_window(self):
        self.root.title("HBILLSOFT — License Keygen")
        self.root.geometry("620x580")
        self.root.minsize(560, 520)
        self.root.configure(bg=BG)
        self.root.resizable(True, True)
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth()  - 620) // 2
        y = (self.root.winfo_screenheight() - 580) // 2
        self.root.geometry(f"620x580+{x}+{y}")

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        outer = tk.Frame(self.root, bg=BG)
        outer.pack(fill="both", expand=True, padx=28, pady=24)
        self._toast_parent = outer

        # Header
        hdr = tk.Frame(outer, bg=BG)
        hdr.pack(fill="x", pady=(0, 18))

        title_row = tk.Frame(hdr, bg=BG)
        title_row.pack(fill="x")
        tk.Label(title_row, text="HBILLSOFT", font=FONT_TITLE, bg=BG, fg=TEXT).pack(side="left")
        tk.Label(title_row, text="  LICENSE KEYGEN",
                 font=FONT_BADGE, bg="#0d2b3e", fg=ACCENT,
                 relief="flat", padx=8, pady=3).pack(side="left", padx=(10, 0))

        tk.Label(hdr, text="VENDOR KEY MANAGEMENT TOOL",
                 font=FONT_SMALL, bg=BG, fg=MUTED).pack(anchor="w", pady=(4, 0))

        # Key status banner (read-only, no browse)
        self.key_status_var = tk.StringVar(value="⏳  Looking for private_key.pem…")
        self.key_banner = tk.Label(
            outer, textvariable=self.key_status_var,
            font=FONT_SMALL, bg="#0d2b26", fg=MUTED,
            relief="flat", padx=12, pady=6, anchor="w"
        )
        self.key_banner.pack(fill="x", pady=(0, 16))

        # ── Section 01: System Code ───────────────────────────────────────────
        self._section_label(outer, "01  SYSTEM CODE")
        card1 = self._card(outer)

        tk.Label(card1, text="System Code  (from customer's activation screen)",
                 font=FONT_SMALL, bg=CARD, fg=MUTED).pack(anchor="w", pady=(0, 6))

        sc_row = tk.Frame(card1, bg=CARD)
        sc_row.pack(fill="x")

        self.sc_var = tk.StringVar()
        self._sc_trace_id = self.sc_var.trace_add("write", self._format_syscode)
        self.sc_entry = tk.Entry(
            sc_row, textvariable=self.sc_var,
            font=FONT_MONO, bg=BG3, fg=ACCENT,
            insertbackground=TEXT, relief="flat", bd=0
        )
        self.sc_entry.pack(side="left", fill="x", expand=True, ipady=9, padx=(0, 8))
        self._style_entry(self.sc_entry)

        tk.Button(
            sc_row, text="Paste", command=self._paste_syscode,
            font=FONT_LABEL, bg=BG3, fg=MUTED,
            activebackground=CARD, activeforeground=TEXT,
            relief="flat", bd=0, cursor="hand2", padx=12, pady=7
        ).pack(side="right")

        # ── Section 02: Duration ──────────────────────────────────────────────
        self._section_label(outer, "02  LICENSE DURATION")
        card2 = self._card(outer)

        dur_row = tk.Frame(card2, bg=CARD)
        dur_row.pack(fill="x")

        self.expiry_var = tk.StringVar(value=self.expiry_options[2][0])
        expiry_menu = ttk.Combobox(
            dur_row, textvariable=self.expiry_var,
            values=[o[0] for o in self.expiry_options],
            state="readonly", font=FONT_BODY, width=14
        )
        expiry_menu.pack(side="left")
        expiry_menu.bind("<<ComboboxSelected>>", lambda e: self._update_expiry_preview())

        self.expiry_preview_var = tk.StringVar()
        tk.Label(dur_row, textvariable=self.expiry_preview_var,
                 font=("Segoe UI", 10, "bold"), bg=CARD, fg=ACCENT).pack(side="left", padx=(14, 0))
        self._update_expiry_preview()

        # ── Generate button ───────────────────────────────────────────────────
        tk.Frame(outer, bg=BG, height=14).pack()
        self.gen_btn = tk.Button(
            outer, text="  Generate License Key",
            command=self._generate_license,
            font=FONT_BTN, bg=ACCENT, fg="#000",
            activebackground="#33c8ff", activeforeground="#000",
            relief="flat", bd=0, cursor="hand2", pady=12
        )
        self.gen_btn.pack(fill="x")
        tk.Frame(outer, bg=BG, height=14).pack()

        # ── Section 03: Output ────────────────────────────────────────────────
        self._section_label(outer, "03  GENERATED LICENSE KEY")
        card3 = self._card(outer)

        self.output_text = tk.Text(
            card3, font=FONT_MONO, bg=BG3, fg=TEXT,
            relief="flat", bd=0, height=4, wrap="word",
            insertbackground=TEXT, state="disabled"
        )
        self.output_text.pack(fill="x", pady=(0, 10))

        out_btns = tk.Frame(card3, bg=CARD)
        out_btns.pack(fill="x")

        self.copy_btn = tk.Button(
            out_btns, text="Copy to Clipboard",
            command=self._copy_key,
            font=FONT_BTN, bg="#0d2b26", fg=SUCCESS,
            activebackground="#0a2020", activeforeground=SUCCESS,
            relief="flat", bd=0, cursor="hand2",
            padx=14, pady=7, state="disabled"
        )
        self.copy_btn.pack(side="left", padx=(0, 8))

        tk.Button(
            out_btns, text="Clear", command=self._clear,
            font=FONT_LABEL, bg=BG3, fg=MUTED,
            activebackground=CARD, activeforeground=TEXT,
            relief="flat", bd=0, cursor="hand2", padx=14, pady=7
        ).pack(side="left")

        # Footer
        tk.Frame(outer, bg=BG, height=10).pack()
        tk.Label(
            outer,
            text="HBILLSOFT © 2026  —  Keep private_key.pem confidential. Never distribute it.",
            font=FONT_SMALL, bg=BG, fg=MUTED
        ).pack()

    # ── Widget helpers ────────────────────────────────────────────────────────

    def _card(self, parent):
        f = tk.Frame(parent, bg=CARD, pady=16, padx=18)
        f.pack(fill="x", pady=(6, 16))
        return f

    def _section_label(self, parent, text):
        tk.Label(parent, text=text, font=("Segoe UI", 8, "bold"), bg=BG, fg=MUTED).pack(anchor="w")

    def _style_entry(self, entry):
        entry.config(highlightbackground=BORDER, highlightcolor=BORDER, highlightthickness=1)
        entry.bind("<FocusIn>",  lambda e: entry.config(highlightbackground=ACCENT, highlightcolor=ACCENT))
        entry.bind("<FocusOut>", lambda e: entry.config(highlightbackground=BORDER, highlightcolor=BORDER))

    # ── Logic ─────────────────────────────────────────────────────────────────

    def _get_days(self) -> int:
        label = self.expiry_var.get()
        for name, days in self.expiry_options:
            if name == label:
                return days
        return 365

    def _update_expiry_preview(self):
        exp = datetime.date.today() + datetime.timedelta(days=self._get_days())
        self.expiry_preview_var.set(f"→  Expires {exp.strftime('%d %b %Y')}")

    def _format_syscode(self, *args):
        raw = self.sc_var.get().replace('-', '').replace(' ', '').upper()[:16]
        parts = [raw[i:i+4] for i in range(0, len(raw), 4)]
        formatted = '-'.join(parts)
        if formatted != self.sc_var.get():
            self.sc_var.trace_remove("write", self._sc_trace_id)
            self.sc_var.set(formatted)
            self._sc_trace_id = self.sc_var.trace_add("write", self._format_syscode)
            self.sc_entry.icursor(tk.END)

    def _paste_syscode(self):
        try:
            self.sc_var.set(self.root.clipboard_get().strip())
        except tk.TclError:
            pass

    # ── Auto key load (no dialog, no browse) ─────────────────────────────────

    def _autoload_key(self):
        if PRIVATE_KEY_PATH.exists():
            try:
                load_private_key_from_file(str(PRIVATE_KEY_PATH))
                with open(PRIVATE_KEY_PATH) as f:
                    self.private_pem = f.read()
                self.key_banner.config(
                    text=f"✓  private_key.pem loaded from project folder",
                    bg="#0d2b26", fg=SUCCESS
                )
                self.key_status_var.set("✓  private_key.pem loaded from project folder")
            except Exception as e:
                self.key_banner.config(
                    text=f"✗  private_key.pem found but invalid: {e}",
                    bg="#2b0d1a", fg=DANGER
                )
                self.key_status_var.set(f"✗  Invalid key: {e}")
        else:
            self.key_banner.config(
                text=f"✗  private_key.pem not found in: {PROJECT_DIR}",
                bg="#2b1400", fg=WARNING
            )
            self.key_status_var.set(f"✗  private_key.pem not found in project folder")

    # ── License generation ────────────────────────────────────────────────────

    def _generate_license(self):
        if not self.private_pem:
            Toast(self._toast_parent, "private_key.pem not loaded — place it in the project folder", "error")
            return

        sc   = self.sc_var.get().strip().upper()
        days = self._get_days()

        if len(sc.replace('-', '')) < 12:
            Toast(self._toast_parent, "Enter a valid System Code", "error")
            self.sc_entry.focus_set()
            return

        try:
            key = generate_license(sc, days, self.private_pem)
            self.output_text.config(state="normal")
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", key)
            self.output_text.config(state="disabled")
            self.copy_btn.config(state="normal")
            exp = (datetime.date.today() + datetime.timedelta(days=days)).strftime('%d %b %Y')
            Toast(self._toast_parent, f"✓  License generated  —  expires {exp}", "success")
        except Exception as e:
            Toast(self._toast_parent, f"Error: {e}", "error")

    def _copy_key(self):
        key = self.output_text.get("1.0", tk.END).strip()
        if key:
            self.root.clipboard_clear()
            self.root.clipboard_append(key)
            Toast(self._toast_parent, "✓  Copied to clipboard", "success")

    def _clear(self):
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state="disabled")
        self.copy_btn.config(state="disabled")


# ── ttk style ─────────────────────────────────────────────────────────────────

def apply_ttk_style():
    style = ttk.Style()
    style.theme_use("clam")
    style.configure(
        "TCombobox",
        fieldbackground=BG3, background=BG3, foreground=TEXT,
        bordercolor=BORDER, arrowcolor=MUTED,
        selectbackground=BG3, selectforeground=TEXT,
        padding=(10, 8), font=("Segoe UI", 10),
    )
    style.map("TCombobox",
              fieldbackground=[("readonly", BG3)],
              foreground=[("readonly", TEXT)],
              selectbackground=[("readonly", BG3)],
              selectforeground=[("readonly", TEXT)])
    style.configure("TScrollbar", background=BORDER, troughcolor=BG2, arrowcolor=MUTED)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    root = tk.Tk()
    apply_ttk_style()
    app = KeygenWindow(root)
    root.mainloop()
