"""
gui_app.py
----------
ChaCha20-Poly1305 AEAD Interactive Demo - redesigned UI.
  - Equal-width sender / receiver panels
  - No auto-hide (text persists until next action)
  - Coloured, structured data display (not raw terminal)
  - Palette: #9BB4C0  #E1D0B3  #A18D6D  #703B3B
"""

import tkinter as tk
from crypto_logic import (
    generate_key,
    encrypt_message,
    decrypt_message,
    tamper_ciphertext,
    bytes_to_hex,
)

# ── Palette ──────────────────────────────────────────────────────────────────
C_STEEL   = "#9BB4C0"
C_LINEN   = "#1C1F24"
C_UMBER   = "#BF3131"
C_CRIMSON = "#BF3131"

C_BG      = "#1C1F24"
C_CARD    = "#252A31"
C_DARK    = "#1A1D22"
C_MUTED   = "#7A8494"

TAG_LABEL   = "#9BB4C0"
TAG_KEY     = "#E1C96B"
TAG_NONCE   = "#9BB4C0"
TAG_CIPHER  = "#B8D4E8"
TAG_MAC_OK  = "#76C99A"
TAG_MAC_ERR = "#561C24"
TAG_PLAIN   = "#E1D0B3"
TAG_WIRE    = "#C8B89A"
TAG_SEP     = "#3A4050"

FONT_UI    = ("Segoe UI", 10)
FONT_BOLD  = ("Segoe UI", 10, "bold")
FONT_SMALL = ("Segoe UI", 9)
FONT_MONO  = ("Consolas", 9)


# ── Rich panel ────────────────────────────────────────────────────────────────

class RichPanel(tk.Frame):
    KINDS = {
        "header":  (TAG_LABEL,   FONT_BOLD),
        "key":     (TAG_KEY,     FONT_MONO),
        "nonce":   (TAG_NONCE,   FONT_MONO),
        "cipher":  (TAG_CIPHER,  FONT_MONO),
        "mac_ok":  (TAG_MAC_OK,  FONT_MONO),
        "mac_err": (TAG_MAC_ERR, FONT_MONO),
        "plain":   (TAG_PLAIN,   ("Segoe UI", 11, "bold")),
        "wire":    (TAG_WIRE,    FONT_MONO),
        "err":     (TAG_MAC_ERR, FONT_UI),
        "muted":   (C_MUTED,     FONT_SMALL),
        "sep":     (TAG_SEP,     FONT_SMALL),
    }

    def __init__(self, parent, height=14, **kw):
        super().__init__(parent, bg=C_DARK, **kw)
        sb = tk.Scrollbar(self, orient="vertical", bg=C_CARD,
                          troughcolor=C_DARK, width=8)
        self._t = tk.Text(
            self, height=height,
            bg=C_DARK, fg=C_LINEN,
            font=FONT_MONO,
            relief="flat", bd=8,
            wrap="word",
            yscrollcommand=sb.set,
            state="disabled",
            cursor="arrow",
            spacing1=2, spacing3=2,
        )
        sb.config(command=self._t.yview)
        sb.pack(side="right", fill="y")
        self._t.pack(side="left", fill="both", expand=True)

        for name, (fg, font) in self.KINDS.items():
            self._t.tag_configure(name, foreground=fg, font=font)
        self._t.tag_configure("indent", lmargin1=12, lmargin2=12)

    def set_placeholder(self, text):
        self._t.config(state="normal")
        self._t.delete("1.0", "end")
        self._t.insert("end", f"\n  {text}", ("muted",))
        self._t.config(state="disabled")

    def render(self, rows):
        self._t.config(state="normal")
        self._t.delete("1.0", "end")
        for kind, text in rows:
            if kind == "sep":
                self._t.insert("end", "  " + "─" * 38 + "\n", ("sep",))
            else:
                self._t.insert("end", text + "\n", (kind, "indent"))
        self._t.config(state="disabled")
        self._t.yview_moveto(0)


# ── App ───────────────────────────────────────────────────────────────────────

class ChaChaApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("ChaCha20-Poly1305  AEAD Demo")
        self.configure(bg=C_BG)
        self.resizable(True, True)
        self.minsize(1050, 700)

        self._key        = generate_key()
        self._enc_result = None
        self._transmitted= None
        self._tampered   = False

        self._build_ui()
        self._center(1200, 800)

    # ── UI structure ──────────────────────────────────────────────────────────

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg=C_STEEL, pady=0)
        hdr.pack(fill="x")

        # Center container for title
        ih = tk.Frame(hdr, bg=C_STEEL, padx=16, pady=12)
        ih.pack(fill="both", expand=True)

        # Shadow layer (offset label drawn first, behind)
        shadow = tk.Label(ih, text="ChaCha20-Poly1305",
                          bg=C_STEEL, fg="#6A8A96",
                          font=("Georgia", 17, "bold"))
        shadow.place(relx=0.5, rely=0.5, anchor="center", x=2, y=2)

        # Title — centered with shadow
        title_frame = tk.Frame(ih, bg=C_STEEL)
        title_frame.pack(expand=True)
        tk.Label(title_frame, text="ChaCha20-Poly1305",
                 bg=C_STEEL, fg=C_LINEN,
                 font=("Georgia", 17, "bold")).pack(side="left")
        tk.Label(title_frame, text="   AEAD Authenticated Encryption Demo",
                 bg=C_STEEL, fg=C_BG,
                 font=("Georgia", 11)).pack(side="left")

        tk.Label(ih, text="Network Security Project  ",
                 bg=C_STEEL, fg=C_BG,
                 font=("Segoe UI", 9)).place(relx=1.0, rely=0.5, anchor="e", x=-8)

        # Body — equal columns
        body = tk.Frame(self, bg=C_BG)
        body.pack(fill="both", expand=True, padx=14, pady=10)
        body.columnconfigure(0, weight=1, uniform="eq")
        body.columnconfigure(1, weight=0)
        body.columnconfigure(2, weight=1, uniform="eq")
        body.rowconfigure(0, weight=1)

        self._build_sender(body)
        self._build_channel(body)
        self._build_receiver(body)

        # Status bar
        self._sv = tk.StringVar(value="Ready — type a message and click Encrypt.")
        self._sb = tk.Label(self, textvariable=self._sv,
                            bg="#111318", fg=C_MUTED,
                            font=("Segoe UI", 9),
                            anchor="w", padx=14, pady=5)
        self._sb.pack(fill="x", side="bottom")

    # ── Sender panel ──────────────────────────────────────────────────────────

    def _build_sender(self, parent):
        card = tk.Frame(parent, bg=C_CARD, relief="flat")
        card.grid(row=0, column=0, sticky="nsew", padx=(0, 5))

        # Title strip
        ts = tk.Frame(card, bg=C_STEEL, pady=9)
        ts.pack(fill="x")
        tk.Label(ts, text="  SENDER", bg=C_STEEL, fg=C_BG,
                 font=("Georgia", 12, "bold")).pack(side="left")
        tk.Label(ts, text="encrypts & transmits  ", bg=C_STEEL, fg="#4A6572",
                 font=("Segoe UI", 8)).pack(side="right")

        b = tk.Frame(card, bg=C_CARD, padx=14, pady=10)
        b.pack(fill="both", expand=True)

        tk.Label(b, text="Plaintext Message", bg=C_CARD, fg=C_STEEL,
                 font=FONT_BOLD).pack(anchor="w", pady=(0, 4))

        self._msg = tk.Text(b, height=3,
                            bg=C_DARK, fg=C_STEEL,
                            font=("Segoe UI", 11),
                            relief="flat", bd=6,
                            wrap="word",
                            insertbackground=C_STEEL)
        self._msg.pack(fill="x", pady=(0, 10))
        self._msg.insert("end", "Hello, this is a secret message!")

        self._btn_enc = tk.Button(
            b, text="Encrypt  \u2192",
            command=self._do_encrypt,
            bg=C_STEEL, fg=C_BG,
            font=("Georgia", 11, "bold"),
            relief="flat", cursor="hand2",
            pady=9, activebackground="#7A9CAC",
        )
        self._btn_enc.pack(fill="x", pady=(0, 14))

        tk.Frame(b, bg="#3A4050", height=1).pack(fill="x", pady=(0, 6))
        tk.Label(b, text="Transmitted Data", bg=C_CARD, fg=C_CRIMSON ,
                 font=FONT_BOLD).pack(anchor="w")
        tk.Label(b, text="nonce  \u00b7  ciphertext  \u00b7  MAC", bg=C_CARD, fg=C_MUTED,
                 font=FONT_SMALL).pack(anchor="w", pady=(0, 6))

        self._tx_panel = RichPanel(b, height=14)
        self._tx_panel.pack(fill="both", expand=True)
        self._tx_panel.set_placeholder("Press Encrypt to see what is transmitted \u2192")

    # ── Channel panel ─────────────────────────────────────────────────────────

    def _build_channel(self, parent):
        card = tk.Frame(parent, bg="#1E2229", relief="flat")
        card.grid(row=0, column=1, sticky="nsew", padx=5)
        card.config(width=215)
        card.pack_propagate(False)

        ts = tk.Frame(card, bg=C_UMBER, pady=9)
        ts.pack(fill="x")
        tk.Label(ts, text="CHANNEL", bg=C_UMBER, fg=C_BG  ,
                 font=("Georgia", 12, "bold")).pack()

        b = tk.Frame(card, bg="#1E2229", padx=14, pady=14)
        b.pack(fill="both", expand=True)

        tk.Label(b, text="Simulate an attacker\ntampering with the\nciphertext in transit:",
                 bg="#1E2229", fg=C_STEEL, font=FONT_UI, justify="center").pack(pady=(8, 14))

        self._tamp_var = tk.StringVar(value="\u2713  Untampered")
        self._tamp_lbl = tk.Label(b, textvariable=self._tamp_var,
                                  bg="#1E2229", fg=TAG_MAC_OK,
                                  font=("Segoe UI", 10, "bold"), justify="center")
        self._tamp_lbl.pack(pady=(0, 14))

        self._btn_tamp = tk.Button(
            b, text="\u2620  Tamper",
            command=self._do_tamper,
            bg=C_CRIMSON, fg=C_LINEN,
            font=("Georgia", 10, "bold"),
            relief="flat", cursor="hand2",
            pady=10, activebackground="#5A2A2A",
        )
        self._btn_tamp.pack(fill="x", pady=(0, 8))

        self._btn_reset = tk.Button(
            b, text="\u21ba  Reset",
            command=self._do_reset,
            bg="#2E3440", fg=C_MUTED,
            font=FONT_UI,
            relief="flat", cursor="hand2",
            pady=7, activebackground="#3A4050",
        )
        self._btn_reset.pack(fill="x", pady=(0, 20))

        tk.Frame(b, bg="#3A4050", height=1).pack(fill="x", pady=(0, 10))

        for num, note in [
            ("1.", "Sender computes MAC\n    over ciphertext."),
            ("2.", "MAC travels with\n    the packet."),
            ("3.", "Receiver recomputes\n    MAC, compares."),
            ("4.", "Any changed bit =\n    different MAC =\n    REJECTED."),
        ]:
            row = tk.Frame(b, bg="#1E2229")
            row.pack(fill="x", pady=2)
            tk.Label(row, text=num, bg="#1E2229", fg=C_CRIMSON,
                     font=("Segoe UI", 9, "bold"), width=3, anchor="n").pack(side="left")
            tk.Label(row, text=note, bg="#1E2229", fg=C_STEEL,
                     font=("Segoe UI", 10, "bold"), justify="left", anchor="nw").pack(side="left")

    # ── Receiver panel ────────────────────────────────────────────────────────

    def _build_receiver(self, parent):
        card = tk.Frame(parent, bg=C_STEEL, relief="flat")
        card.grid(row=0, column=2, sticky="nsew", padx=(5, 0))

        ts = tk.Frame(card, bg=C_STEEL, pady=9)
        ts.pack(fill="x")
        tk.Label(ts, text="  RECEIVER", bg=C_STEEL, fg=C_BG,
                 font=("Georgia", 12, "bold")).pack(side="left")
        tk.Label(ts, text="verifies & decrypts  ", bg=C_STEEL, fg=C_BG,
                 font=("Segoe UI", 8)).pack(side="right")

        b = tk.Frame(card, bg=C_CARD, padx=14, pady=10)
        b.pack(fill="both", expand=True)

        # Plaintext display (mirrors sender's input box — read-only)
        tk.Label(b, text="Decrypted Message", bg=C_CARD, fg=C_STEEL,
                 font=FONT_BOLD).pack(anchor="w", pady=(0, 4))

        self._dec_display = tk.Text(b, height=3,
                                    bg=C_DARK, fg=C_STEEL,
                                    font=("Segoe UI", 11),
                                    relief="flat", bd=6,
                                    wrap="word",
                                    state="disabled",
                                    cursor="arrow")
        self._dec_display.pack(fill="x", pady=(0, 10))

        # Decrypt button below the display box
        self._btn_dec = tk.Button(
            b, text="\u2190  Decrypt & Verify",
            command=self._do_decrypt,
            bg=C_STEEL, fg=C_BG,
            font=("Georgia", 11, "bold"),
            relief="flat", cursor="hand2",
            pady=9, activebackground="#7A9CAC",
        )
        self._btn_dec.pack(fill="x", pady=(0, 6))

        tk.Frame(b, bg="#3A4050", height=1).pack(fill="x", pady=(0, 6))

        tk.Label(b, text="Decryption Details", bg=C_CARD, fg=C_CRIMSON ,
                 font=FONT_BOLD).pack(anchor="w")
        tk.Label(b, text="MAC check  \u00b7  plaintext or error", bg=C_CARD, fg=C_MUTED,
                 font=FONT_SMALL).pack(anchor="w", pady=(0, 6))

        self._rx_panel = RichPanel(b, height=14)
        self._rx_panel.pack(fill="both", expand=True)
        self._rx_panel.set_placeholder("Press Decrypt & Verify to process the packet \u2190")

    # ── Action handlers ───────────────────────────────────────────────────────

    def _do_encrypt(self):
        msg = self._msg.get("1.0", "end").strip()
        if not msg:
            self._status("Please enter a message first.", C_CRIMSON)
            return
        self._btn_enc.config(state="disabled", text="Encrypting...")
        self.update_idletasks()
        try:
            result = encrypt_message(msg, self._key)
        except Exception as exc:
            self._status(f"Error: {exc}", C_CRIMSON)
            self._btn_enc.config(state="normal", text="Encrypt  \u2192")
            return
        self._enc_result  = result
        self._transmitted = result["transmitted"]
        self._tampered    = False
        self._tamp_var.set("\u2713  Untampered")
        self._tamp_lbl.config(fg=TAG_MAC_OK)
        self._rx_panel.set_placeholder("Press Decrypt & Verify to process the packet \u2190")
        self._dec_display.config(state="normal")
        self._dec_display.delete("1.0", "end")
        self._dec_display.config(state="disabled")
        self._tx_panel.render(self._tx_rows(result, False))
        self._btn_enc.config(state="normal", text="Encrypt  \u2192")
        self._status("Encryption complete.", C_STEEL)

    def _do_tamper(self):
        if self._enc_result is None:
            self._status("Encrypt a message first.", C_CRIMSON)
            return
        self._transmitted = tamper_ciphertext(self._enc_result["transmitted"])
        self._tampered = True
        self._tamp_var.set("\u2620  TAMPERED!")
        self._tamp_lbl.config(fg=TAG_MAC_ERR)
        self._tx_panel.render(self._tx_rows(self._enc_result, True))
        self._status("Ciphertext tampered! Click Decrypt to see detection.", C_CRIMSON)

    def _do_reset(self):
        if self._enc_result is None:
            return
        self._transmitted = self._enc_result["transmitted"]
        self._tampered = False
        self._tamp_var.set("\u2713  Untampered")
        self._tamp_lbl.config(fg=TAG_MAC_OK)
        self._tx_panel.render(self._tx_rows(self._enc_result, False))
        self._rx_panel.set_placeholder("Press Decrypt & Verify to process the packet \u2190")
        self._dec_display.config(state="normal")
        self._dec_display.delete("1.0", "end")
        self._dec_display.config(state="disabled")
        self._status("Packet restored to original.", C_STEEL)

    def _do_decrypt(self):
        if self._transmitted is None:
            self._status("Encrypt a message first.", C_CRIMSON)
            return
        self._btn_dec.config(state="disabled", text="Verifying...")
        self.update_idletasks()
        result = decrypt_message(self._transmitted, self._key)
        self._rx_panel.render(self._rx_rows(result))

        # Update the display box
        self._dec_display.config(state="normal")
        self._dec_display.delete("1.0", "end")
        if result["success"]:
            self._dec_display.insert("end", result["plaintext"])
            self._dec_display.config(fg=C_STEEL)
        else:
            self._dec_display.insert("end", "⚠ Decryption failed — message rejected")
            self._dec_display.config(fg=TAG_MAC_ERR)
        self._dec_display.config(state="disabled")

        if result["success"]:
            self._status("Decryption successful \u2014 integrity and authenticity verified.", TAG_MAC_OK)
        else:
            self._status("Tamper detected \u2014 Poly1305 MAC mismatch. Message rejected.", C_CRIMSON)
        self._btn_dec.config(state="normal", text="\u2190  Decrypt & Verify")

    # ── Row builders ──────────────────────────────────────────────────────────

    def _tx_rows(self, r: dict, tampered: bool) -> list:
        wire = bytes_to_hex(self._transmitted if tampered else r["transmitted"])
        rows = [
            ("header", "  KEY  (secret \u2014 never transmitted)"),
            ("sep",    ""),
            ("key",    "  " + bytes_to_hex(r["key"])),
            ("sep",    ""),
            ("header", "  NONCE  (12 bytes \u00b7 random \u00b7 sent in clear)"),
            ("sep",    ""),
            ("nonce",  "  " + bytes_to_hex(r["nonce"])),
            ("sep",    ""),
            ("header", "  CIPHERTEXT  (ChaCha20 stream cipher output)"),
            ("sep",    ""),
            ("cipher", "  " + bytes_to_hex(r["ciphertext"])),
            ("sep",    ""),
            ("header", "  POLY1305 MAC  (16-byte authentication tag)"),
            ("sep",    ""),
            ("mac_ok", "  " + bytes_to_hex(r["mac"])),
            ("sep",    ""),
        ]
        if tampered:
            rows += [
                ("mac_err", "  WIRE PACKET  \u2190  \u2620 BIT FLIPPED AT BYTE 12"),
                ("sep",     ""),
                ("mac_err", "  " + wire),
            ]
        else:
            rows += [
                ("header", "  WIRE PACKET  (nonce | ciphertext | MAC)"),
                ("sep",    ""),
                ("wire",   "  " + wire),
            ]
        return rows

    def _rx_rows(self, r: dict) -> list:
        mac_hex = bytes_to_hex(r["received_mac"])
        if r["success"]:
            return [
                ("mac_ok", "  \u2713  Authentication PASSED  \u2014  Message is genuine"),
                ("sep",    ""),
                ("header", "  MAC VERIFICATION"),
                ("sep",    ""),
                ("muted",  "  Received MAC tag:"),
                ("mac_ok", "  " + mac_hex),
                ("muted",  ""),
                ("mac_ok", "  \u2713  Tags match \u2014 message is authentic and unmodified"),
            ]
        else:
            return [
                ("mac_err", "  \u2717  Authentication FAILED  \u2014  Message REJECTED"),
                ("sep",     ""),
                ("header",  "  MAC VERIFICATION"),
                ("sep",     ""),
                ("muted",   "  Received MAC tag:"),
                ("mac_err", "  " + mac_hex),
                ("muted",   ""),
                ("mac_err", "  \u2717  Tags do NOT match \u2014 tampering detected"),
                ("sep",     ""),
                ("header",  "  ERROR"),
                ("sep",     ""),
                ("err",     "  " + r["error"].replace("\n", "\n  ")),
                ("muted",   ""),
                ("muted",   "  Decryption was NOT performed."),
                ("muted",   "  The corrupted packet is silently dropped."),
            ]

    # ── Utility ───────────────────────────────────────────────────────────────

    def _status(self, msg: str, color: str = C_MUTED):
        self._sv.set(msg)
        self._sb.config(fg=color)

    def _center(self, w: int, h: int):
        self.update_idletasks()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")


if __name__ == "__main__":
    app = ChaChaApp()
    app.mainloop()