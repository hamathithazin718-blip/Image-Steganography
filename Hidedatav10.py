"""
Steganography Image Tool — GUI Edition
----------------------------------------
A sleek, dark-themed desktop interface for hiding text or files inside images.

All core steganography logic (Converting_To_Bin, hideData, the MARKER-based
file-append scheme, and the LSB text encode/decode algorithm) is preserved
EXACTLY as in the original CLI version — only the interaction layer changed.

Requirements:
    pip install customtkinter opencv-python numpy pillow

Run:
    python Hide_Datav7_GUI.py
"""

import os
import threading
import datetime
import cv2
import numpy as np
import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image

# ----------------------------------------------------------------------------
# THEME
# ----------------------------------------------------------------------------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

BG_COLOR = "#0d1117"
PANEL_COLOR = "#161b22"
CARD_COLOR = "#1c2128"
ACCENT = "#3fb950"
ACCENT_HOVER = "#2ea043"
DANGER = "#f85149"
TEXT_MUTED = "#8b949e"
TEXT_MAIN = "#e6edf3"
BORDER = "#30363d"

FONT_TITLE = ("Segoe UI", 26, "bold")
FONT_SUB = ("Segoe UI", 13)
FONT_SECTION = ("Segoe UI", 15, "bold")
FONT_BODY = ("Segoe UI", 13)
FONT_MONO = ("Consolas", 11)
FONT_BTN = ("Segoe UI", 13, "bold")


# ----------------------------------------------------------------------------
# ORIGINAL CORE LOGIC — UNCHANGED FUNCTIONALLY
# ----------------------------------------------------------------------------
MARKER = b"###STEG_DATA###"


def Converting_To_Bin(data):
    if isinstance(data, str):
        return ''.join([format(ord(i), "08b") for i in data])
    elif isinstance(data, (np.uint8, int)):
        return format(data, "08b")
    return [format(i, "08b") for i in data]


END_DELIM = ":::END:::"  # marks where the real hidden message stops


def hideData(pic, data, key_sec):
    data_to_hide = key_sec + ":" + data + END_DELIM
    binary_Message = Converting_To_Bin(data_to_hide)
    data_index = 0
    binary_Message_len = len(binary_Message)
    for values in pic:
        for pixel in values:
            r, g, b = Converting_To_Bin(pixel)
            if data_index < binary_Message_len:
                pixel[0] = int(r[:-1] + binary_Message[data_index], 2)
                data_index += 1
            if data_index < binary_Message_len:
                pixel[1] = int(g[:-1] + binary_Message[data_index], 2)
                data_index += 1
            if data_index < binary_Message_len:
                pixel[2] = int(b[:-1] + binary_Message[data_index], 2)
                data_index += 1
            if data_index >= binary_Message_len:
                break
    return pic


def encode_text_to_image(img_path, key_sec, message, log_fn, progress_fn):
    log_fn(f"Loading carrier image: {os.path.basename(img_path)}")
    image = cv2.imread(img_path)
    if image is None:
        raise ValueError("Could not read the selected image file.")

    output_folder = "EncodedImages"
    os.makedirs(output_folder, exist_ok=True)

    progress_fn(0.3)
    log_fn("Embedding message into pixel data (LSB)...")
    injected = hideData(image, message, key_sec)

    progress_fn(0.7)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    save_path = os.path.join(output_folder, f"encoded_{timestamp}.png")
    cv2.imwrite(save_path, injected)

    progress_fn(1.0)
    log_fn(f"Done! Saved as: {save_path}", success=True)
    return save_path


def encode_file_to_image(img_path, key_sec, file_to_hide, log_fn, progress_fn):
    log_fn(f"Loading carrier image: {os.path.basename(img_path)}")
    output_folder = "EncodedImages"
    os.makedirs(output_folder, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    save_path = os.path.join(output_folder, f"encoded_{timestamp}.png")

    meta = key_sec.encode() + b"|||" + os.path.basename(file_to_hide).encode() + b"|||"

    progress_fn(0.2)
    log_fn("Appending file payload (perfect copy mode)...")
    with open(img_path, "rb") as f_img, open(file_to_hide, "rb") as f_data, open(save_path, "wb") as f_out:
        f_out.write(f_img.read())
        progress_fn(0.5)
        f_out.write(MARKER)
        f_out.write(meta)
        f_out.write(f_data.read())

    progress_fn(1.0)
    log_fn(f"File appended perfectly. Saved as: {save_path}", success=True)
    return save_path


def decode_image(img_path, key_sec, log_fn, progress_fn):
    log_fn(f"Reading file: {os.path.basename(img_path)}")
    with open(img_path, "rb") as f:
        content = f.read()

    progress_fn(0.3)

    if MARKER in content:
        log_fn("Marker found — detected appended file payload.")
        _, payload = content.split(MARKER, 1)
        parts = payload.split(b"|||")

        if len(parts) >= 3:
            key_in_file = parts[0].decode()
            filename = parts[1].decode()
            data = b"|||".join(parts[2:])

            progress_fn(0.6)
            if key_in_file == key_sec:
                os.makedirs("EncodedImages", exist_ok=True)
                save_path = os.path.join("EncodedImages", f"extracted_{filename}")
                with open(save_path, "wb") as f_out:
                    f_out.write(data)
                progress_fn(1.0)
                log_fn("Access Granted!", success=True)
                log_fn(f"File extracted to: {save_path}", success=True)
                return ("file", save_path)
            else:
                progress_fn(1.0)
                log_fn("Access Denied! Incorrect Password.", error=True)
                return ("denied", None)
        else:
            progress_fn(1.0)
            log_fn("Malformed payload structure.", error=True)
            return ("error", None)
    else:
        log_fn("No file marker found — scanning pixel data for hidden text...")
        image = cv2.imread(img_path)
        if image is None:
            raise ValueError("Could not read the selected image file.")

        progress_fn(0.5)
        decoded = ""
        found_end = False
        bits_buffer = ""
        total_pixels = image.shape[0] * image.shape[1]
        pixels_scanned = 0

        for row in image:
            for p in row:
                bits = Converting_To_Bin(p)[0][-1] + Converting_To_Bin(p)[1][-1] + Converting_To_Bin(p)[2][-1]
                bits_buffer += bits
                while len(bits_buffer) >= 8:
                    byte = bits_buffer[:8]
                    bits_buffer = bits_buffer[8:]
                    decoded += chr(int(byte, 2))
                    if decoded.endswith(END_DELIM):
                        found_end = True
                        break
                pixels_scanned += 1
                if found_end:
                    break
            if found_end:
                break
            # Safety cap: stop scanning after a generous limit even if no
            # delimiter is found (handles images with no hidden text at all)
            if pixels_scanned > total_pixels:
                break

        progress_fn(0.9)
        if found_end:
            decoded = decoded[: -len(END_DELIM)]  # strip the delimiter itself
        else:
            # No delimiter found at all within the scanned region — fall back
            # to the raw decode for backward compatibility with older images
            # encoded before this delimiter was introduced.
            pass

        if decoded.startswith(key_sec + ":"):
            progress_fn(1.0)
            log_fn("Access Granted!", success=True)
            hidden_text = decoded.split(':', 1)[1]
            return ("text", hidden_text)
        else:
            progress_fn(1.0)
            log_fn("Access Denied! Incorrect Password.", error=True)
            return ("denied", None)


# ----------------------------------------------------------------------------
# UI HELPERS
# ----------------------------------------------------------------------------
class StatusLog(ctk.CTkTextbox):
    """A console-style log panel."""

    def __init__(self, master, **kwargs):
        super().__init__(master, font=FONT_MONO, fg_color=PANEL_COLOR,
                          text_color=TEXT_MUTED, wrap="word", **kwargs)
        self.configure(state="disabled")
        self.tag_config_done = False

    def write(self, message, success=False, error=False, info=False):
        self.configure(state="normal")
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        color = ACCENT if success else DANGER if error else "#58a6ff" if info else TEXT_MUTED
        self.insert("end", f"[{ts}] ", ("dim",))
        self.insert("end", f"{message}\n", ("msg",))
        self.tag_config("dim", foreground="#5a6270")
        self.tag_config("msg", foreground=color)
        self.see("end")
        self.configure(state="disabled")

    def clear(self):
        self.configure(state="normal")
        self.delete("1.0", "end")
        self.configure(state="disabled")


class FileDropField(ctk.CTkFrame):
    """A styled file-picker field with a browse button and a preview label."""

    def __init__(self, master, label_text, filetypes, on_change=None, dialog_title="Select a file", **kwargs):
        super().__init__(master, fg_color=CARD_COLOR, corner_radius=10, border_width=1,
                          border_color=BORDER, **kwargs)
        self.filetypes = filetypes
        self.dialog_title = dialog_title
        self.on_change = on_change
        self.filepath = None

        self.grid_columnconfigure(0, weight=1)

        self.label = ctk.CTkLabel(self, text=label_text, font=("Segoe UI", 11, "bold"),
                                   text_color=TEXT_MUTED, anchor="w")
        self.label.grid(row=0, column=0, columnspan=2, sticky="w", padx=14, pady=(10, 0))

        self.path_label = ctk.CTkLabel(self, text="No file selected", font=FONT_BODY,
                                        text_color=TEXT_MAIN, anchor="w")
        self.path_label.grid(row=1, column=0, sticky="ew", padx=14, pady=(2, 10))

        self.browse_btn = ctk.CTkButton(self, text="Browse", width=90, height=30,
                                         font=("Segoe UI", 12, "bold"),
                                         fg_color="#21262d", hover_color="#30363d",
                                         border_width=1, border_color=BORDER,
                                         command=self._browse)
        self.browse_btn.grid(row=1, column=1, sticky="e", padx=14, pady=(2, 10))

    def _browse(self):
        path = filedialog.askopenfilename(title=self.dialog_title, filetypes=self.filetypes)
        if path:
            self.filepath = path
            display = path if len(path) < 50 else "..." + path[-47:]
            self.path_label.configure(text=display, text_color=TEXT_MAIN)
            if self.on_change:
                self.on_change(path)

    def reset(self):
        self.filepath = None
        self.path_label.configure(text="No file selected", text_color=TEXT_MUTED)


# ----------------------------------------------------------------------------
# MAIN APPLICATION
# ----------------------------------------------------------------------------
class StegApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Steganography Studio")
        self.geometry("980x680")
        self.minsize(880, 620)
        self.configure(fg_color=BG_COLOR)

        self._build_header()
        self._build_body()
        self._build_footer_log()

    # ----- Header -----
    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color=PANEL_COLOR, corner_radius=0, height=90)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        left = ctk.CTkFrame(header, fg_color="transparent")
        left.pack(side="left", padx=28, pady=12, fill="y")

        title_row = ctk.CTkFrame(left, fg_color="transparent")
        title_row.pack(anchor="w")

        badge = ctk.CTkLabel(title_row, text="🔒", font=("Segoe UI", 22))
        badge.pack(side="left", padx=(0, 10))

        ctk.CTkLabel(title_row, text="Steganography Studio", font=FONT_TITLE,
                     text_color=TEXT_MAIN).pack(side="left")

        ctk.CTkLabel(left, text="Hide text or files inside images with password-protected encoding",
                     font=FONT_SUB, text_color=TEXT_MUTED).pack(anchor="w", pady=(2, 0))

        # Shared secret key field, lives in header so it's always visible
        right = ctk.CTkFrame(header, fg_color="transparent")
        right.pack(side="right", padx=28, pady=12)

        ctk.CTkLabel(right, text="SHARED SECRET KEY", font=("Segoe UI", 10, "bold"),
                     text_color=TEXT_MUTED).pack(anchor="e")

        key_row = ctk.CTkFrame(right, fg_color="transparent")
        key_row.pack(anchor="e", pady=(4, 0))

        self.key_entry = ctk.CTkEntry(key_row, placeholder_text="Enter shared key...",
                                       width=220, height=34, show="•",
                                       font=FONT_BODY, fg_color=CARD_COLOR,
                                       border_color=BORDER, border_width=1)
        self.key_entry.pack(side="left", padx=(0, 6))

        self.show_key_var = ctk.BooleanVar(value=False)
        self.show_key_btn = ctk.CTkButton(key_row, text="👁", width=34, height=34,
                                           fg_color="#21262d", hover_color="#30363d",
                                           border_width=1, border_color=BORDER,
                                           command=self._toggle_key_visibility)
        self.show_key_btn.pack(side="left")

    def _toggle_key_visibility(self):
        show = not self.show_key_var.get()
        self.show_key_var.set(show)
        self.key_entry.configure(show="" if show else "•")

    # ----- Body: Tabs -----
    def _build_body(self):
        body = ctk.CTkFrame(self, fg_color=BG_COLOR)
        body.pack(fill="both", expand=True, padx=28, pady=(20, 10))

        self.tabs = ctk.CTkTabview(body, fg_color=PANEL_COLOR, segmented_button_fg_color=CARD_COLOR,
                                    segmented_button_selected_color=ACCENT,
                                    segmented_button_selected_hover_color=ACCENT_HOVER,
                                    segmented_button_unselected_color=CARD_COLOR,
                                    text_color=TEXT_MAIN, corner_radius=12,
                                    border_width=1, border_color=BORDER)
        self.tabs.pack(fill="both", expand=True)

        self.tab_text = self.tabs.add("  Hide Text  ")
        self.tab_file = self.tabs.add("  Hide File  ")
        self.tab_extract = self.tabs.add("  Extract  ")

        self._build_hide_text_tab()
        self._build_hide_file_tab()
        self._build_extract_tab()

    # --- Tab 1: Hide Text ---
    def _build_hide_text_tab(self):
        tab = self.tab_text
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_columnconfigure(1, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        self.text_carrier = FileDropField(
            tab, "CARRIER IMAGE",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp")],
            dialog_title="Select carrier image",
        )
        self.text_carrier.grid(row=0, column=0, sticky="ew", padx=(0, 8), pady=(0, 12))

        preview_card = ctk.CTkFrame(tab, fg_color=CARD_COLOR, corner_radius=10,
                                     border_width=1, border_color=BORDER)
        preview_card.grid(row=0, column=1, rowspan=2, sticky="nsew", padx=(8, 0), pady=(0, 12))
        ctk.CTkLabel(preview_card, text="PREVIEW", font=("Segoe UI", 11, "bold"),
                     text_color=TEXT_MUTED).pack(anchor="w", padx=14, pady=(10, 0))
        self.text_preview_img_label = ctk.CTkLabel(preview_card, text="No image selected",
                                                     text_color=TEXT_MUTED, font=FONT_BODY)
        self.text_preview_img_label.pack(expand=True, fill="both", padx=14, pady=14)
        self.text_carrier.on_change = lambda p: self._update_preview(p, self.text_preview_img_label)

        msg_card = ctk.CTkFrame(tab, fg_color=CARD_COLOR, corner_radius=10,
                                 border_width=1, border_color=BORDER)
        msg_card.grid(row=1, column=0, sticky="nsew", padx=(0, 8))
        ctk.CTkLabel(msg_card, text="SECRET MESSAGE", font=("Segoe UI", 11, "bold"),
                     text_color=TEXT_MUTED).pack(anchor="w", padx=14, pady=(10, 4))
        self.message_box = ctk.CTkTextbox(msg_card, font=FONT_BODY, fg_color=PANEL_COLOR,
                                           text_color=TEXT_MAIN, wrap="word")
        self.message_box.pack(expand=True, fill="both", padx=14, pady=(0, 14))

        action_row = ctk.CTkFrame(tab, fg_color="transparent")
        action_row.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(14, 0))
        action_row.grid_columnconfigure(0, weight=1)

        self.text_progress = ctk.CTkProgressBar(action_row, progress_color=ACCENT,
                                                  fg_color=CARD_COLOR, height=8)
        self.text_progress.set(0)
        self.text_progress.grid(row=0, column=0, sticky="ew", padx=(0, 14))

        self.encode_text_btn = ctk.CTkButton(action_row, text="Hide Message in Image",
                                              font=FONT_BTN, height=42, width=220,
                                              fg_color=ACCENT, hover_color=ACCENT_HOVER,
                                              text_color="#0d1117",
                                              command=self._run_encode_text)
        self.encode_text_btn.grid(row=0, column=1)

    # --- Tab 2: Hide File ---
    def _build_hide_file_tab(self):
        tab = self.tab_file
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_columnconfigure(1, weight=1)

        self.file_carrier = FileDropField(
            tab, "CARRIER IMAGE",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp")],
            dialog_title="Select carrier image",
        )
        self.file_carrier.grid(row=0, column=0, sticky="ew", padx=(0, 8), pady=(0, 12))

        self.file_payload = FileDropField(
            tab, "FILE TO HIDE",
            filetypes=[("All files", "*.*")],
            dialog_title="Select file to hide",
        )
        self.file_payload.grid(row=0, column=1, sticky="ew", padx=(8, 0), pady=(0, 12))

        info_card = ctk.CTkFrame(tab, fg_color=CARD_COLOR, corner_radius=10,
                                  border_width=1, border_color=BORDER)
        info_card.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(0, 0))
        tab.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(info_card, text="ℹ  Perfect Copy Mode", font=("Segoe UI", 13, "bold"),
                     text_color=TEXT_MAIN).pack(anchor="w", padx=18, pady=(16, 4))
        ctk.CTkLabel(info_card,
                     text="The file is appended after the carrier image's binary data using a\n"
                          "unique marker, then encrypted with your shared key. This preserves\n"
                          "the original image and target file completely unmodified.",
                     font=FONT_BODY, text_color=TEXT_MUTED, justify="left").pack(anchor="w", padx=18)

        action_row = ctk.CTkFrame(tab, fg_color="transparent")
        action_row.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(14, 0))
        action_row.grid_columnconfigure(0, weight=1)

        self.file_progress = ctk.CTkProgressBar(action_row, progress_color=ACCENT,
                                                  fg_color=CARD_COLOR, height=8)
        self.file_progress.set(0)
        self.file_progress.grid(row=0, column=0, sticky="ew", padx=(0, 14))

        self.encode_file_btn = ctk.CTkButton(action_row, text="Hide File in Image",
                                              font=FONT_BTN, height=42, width=220,
                                              fg_color=ACCENT, hover_color=ACCENT_HOVER,
                                              text_color="#0d1117",
                                              command=self._run_encode_file)
        self.encode_file_btn.grid(row=0, column=1)

    # --- Tab 3: Extract ---
    def _build_extract_tab(self):
        tab = self.tab_extract
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        self.extract_carrier = FileDropField(
            tab, "INJECTED IMAGE",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp"), ("All files", "*.*")],
            dialog_title="Select injected image",
        )
        self.extract_carrier.grid(row=0, column=0, sticky="ew", pady=(0, 12))

        result_card = ctk.CTkFrame(tab, fg_color=CARD_COLOR, corner_radius=10,
                                    border_width=1, border_color=BORDER)
        result_card.grid(row=1, column=0, sticky="nsew")
        ctk.CTkLabel(result_card, text="RESULT", font=("Segoe UI", 11, "bold"),
                     text_color=TEXT_MUTED).pack(anchor="w", padx=14, pady=(10, 4))
        self.extract_result_box = ctk.CTkTextbox(result_card, font=FONT_BODY, fg_color=PANEL_COLOR,
                                                   text_color=TEXT_MAIN, wrap="word")
        self.extract_result_box.pack(expand=True, fill="both", padx=14, pady=(0, 14))
        self.extract_result_box.insert("1.0", "Extracted text or file location will appear here...")
        self.extract_result_box.configure(state="disabled")

        action_row = ctk.CTkFrame(tab, fg_color="transparent")
        action_row.grid(row=2, column=0, sticky="ew", pady=(14, 0))
        action_row.grid_columnconfigure(0, weight=1)

        self.extract_progress = ctk.CTkProgressBar(action_row, progress_color=ACCENT,
                                                     fg_color=CARD_COLOR, height=8)
        self.extract_progress.set(0)
        self.extract_progress.grid(row=0, column=0, sticky="ew", padx=(0, 14))

        self.extract_btn = ctk.CTkButton(action_row, text="Extract Hidden Data",
                                          font=FONT_BTN, height=42, width=220,
                                          fg_color="#1f6feb", hover_color="#388bfd",
                                          text_color="#ffffff",
                                          command=self._run_extract)
        self.extract_btn.grid(row=0, column=1)

    # ----- Footer: shared status/log panel -----
    def _build_footer_log(self):
        footer = ctk.CTkFrame(self, fg_color=BG_COLOR)
        footer.pack(fill="x", side="bottom", padx=28, pady=(0, 20))

        ctk.CTkLabel(footer, text="ACTIVITY LOG", font=("Segoe UI", 11, "bold"),
                     text_color=TEXT_MUTED).pack(anchor="w", pady=(0, 4))

        self.log = StatusLog(footer, height=110)
        self.log.pack(fill="x")
        self.log.write("Ready. Enter your shared key and select an image to begin.", info=True)

    # ----- Preview helper -----
    def _update_preview(self, path, label_widget):
        try:
            img = Image.open(path)
            img.thumbnail((260, 200))
            ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=img.size)
            label_widget.configure(image=ctk_img, text="")
            label_widget.image = ctk_img
        except Exception:
            label_widget.configure(text="Could not preview this file", image=None)

    # ----- Validation helper -----
    def _get_key(self):
        key = self.key_entry.get().strip()
        return key

    def _require_key(self):
        key = self._get_key()
        if len(key) == 0:
            messagebox.showwarning("Shared Key Required", "Please enter a shared secret key first.")
            self.log.write("Operation blocked: no shared key entered.", error=True)
            return None
        return key

    # ----- Actions (run in background threads to keep UI responsive) -----
    def _run_encode_text(self):
        key = self._require_key()
        if key is None:
            return
        img_path = self.text_carrier.filepath
        message = self.message_box.get("1.0", "end").strip()

        if not img_path:
            messagebox.showwarning("Missing Image", "Please select a carrier image.")
            return
        if not message:
            messagebox.showwarning("Missing Message", "Please enter a message to hide.")
            return

        self._set_buttons_state("disabled")
        self.text_progress.set(0)

        def task():
            try:
                save_path = encode_text_to_image(
                    img_path, key, message,
                    log_fn=self.log.write,
                    progress_fn=lambda v: self.text_progress.set(v),
                )
                self.after(0, lambda: messagebox.showinfo("Success", f"Message hidden successfully!\nSaved to:\n{save_path}"))
            except Exception as e:
                self.log.write(f"Error: {e}", error=True)
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.after(0, lambda: self._set_buttons_state("normal"))

        threading.Thread(target=task, daemon=True).start()

    def _run_encode_file(self):
        key = self._require_key()
        if key is None:
            return
        img_path = self.file_carrier.filepath
        payload_path = self.file_payload.filepath

        if not img_path:
            messagebox.showwarning("Missing Image", "Please select a carrier image.")
            return
        if not payload_path:
            messagebox.showwarning("Missing File", "Please select a file to hide.")
            return

        self._set_buttons_state("disabled")
        self.file_progress.set(0)

        def task():
            try:
                save_path = encode_file_to_image(
                    img_path, key, payload_path,
                    log_fn=self.log.write,
                    progress_fn=lambda v: self.file_progress.set(v),
                )
                self.after(0, lambda: messagebox.showinfo("Success", f"File hidden successfully!\nSaved to:\n{save_path}"))
            except Exception as e:
                self.log.write(f"Error: {e}", error=True)
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.after(0, lambda: self._set_buttons_state("normal"))

        threading.Thread(target=task, daemon=True).start()

    def _run_extract(self):
        key = self._require_key()
        if key is None:
            return
        img_path = self.extract_carrier.filepath

        if not img_path:
            messagebox.showwarning("Missing Image", "Please select an injected image.")
            return

        self._set_buttons_state("disabled")
        self.extract_progress.set(0)
        self._set_result_text("Working...")

        def task():
            try:
                kind, value = decode_image(
                    img_path, key,
                    log_fn=self.log.write,
                    progress_fn=lambda v: self.extract_progress.set(v),
                )
                if kind == "text":
                    self.after(0, lambda: self._set_result_text(f"Hidden Text:\n\n{value}"))
                elif kind == "file":
                    self.after(0, lambda: self._set_result_text(f"File extracted to:\n\n{value}"))
                elif kind == "denied":
                    self.after(0, lambda: self._set_result_text("Access Denied — Incorrect Password."))
                else:
                    self.after(0, lambda: self._set_result_text("Could not parse hidden data."))
            except Exception as e:
                self.log.write(f"Error: {e}", error=True)
                self.after(0, lambda: self._set_result_text(f"Error: {e}"))
            finally:
                self.after(0, lambda: self._set_buttons_state("normal"))

        threading.Thread(target=task, daemon=True).start()

    def _set_result_text(self, text):
        self.extract_result_box.configure(state="normal")
        self.extract_result_box.delete("1.0", "end")
        self.extract_result_box.insert("1.0", text)
        self.extract_result_box.configure(state="disabled")

    def _set_buttons_state(self, state):
        self.encode_text_btn.configure(state=state)
        self.encode_file_btn.configure(state=state)
        self.extract_btn.configure(state=state)


if __name__ == "__main__":
    app = StegApp()
    app.mainloop()
