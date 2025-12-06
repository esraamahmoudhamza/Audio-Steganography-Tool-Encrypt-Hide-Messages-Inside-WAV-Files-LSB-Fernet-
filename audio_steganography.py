"""
Audio Steganography Tool
Single-file application using CustomTkinter + Fernet (AES via cryptography).
Features:
- Hide encrypted text inside WAV using LSB steganography.
- Header stored inside the audio: magic(4) + salt(16) + encrypted_length(8).
- Automatic capacity check.
- Improved GUI: status label, file path display, output path display, show/hide password,
  extracted text displayed in the main TextBox, Clear Fields button.
"""

import customtkinter as ctk
from tkinter import filedialog, messagebox
from tkinter import simpledialog
import wave
import struct
import os
import threading
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# --- Constants ---
MAGIC = b"STEG"               # 4 bytes magic to identify our payload
SALT_SIZE = 16                # bytes
HEADER_FMT = ">4s16sQ"        # magic (4), salt (16), encrypted_length (unsigned long long 8 bytes)
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # should be 28
FONT_NAME = ("Arial", 12)


# ----------------------------- Crypto / helpers -----------------------------
# Function: derive a Fernet key from a password and salt
def derive_fernet_key(password: str, salt: bytes) -> bytes:
    """
    Derive a Fernet-compatible key from password and salt using PBKDF2-HMAC-SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return key


# Function: encrypt plain text with password, return (encrypted_bytes, salt)
def encrypt_message(password: str, message: str):
    """
    Encrypt message using Fernet, with key derived from password and a random salt.
    Returns encrypted bytes and the salt used.
    """
    salt = os.urandom(SALT_SIZE)
    key = derive_fernet_key(password, salt)
    cipher = Fernet(key)
    encrypted = cipher.encrypt(message.encode("utf-8"))
    return encrypted, salt


# Function: decrypt encrypted bytes with password and salt
def decrypt_message(password: str, encrypted_bytes: bytes, salt: bytes) -> str:
    """
    Derive key from password and salt, then decrypt encrypted_bytes with Fernet.
    Returns the decrypted string.
    """
    key = derive_fernet_key(password, salt)
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_bytes).decode("utf-8")


# ----------------------------- Steganography -----------------------------
# Function: calculate maximum storable bytes for given WAV file
def calculate_capacity_bytes(wav_path: str) -> int:
    """
    Calculate maximum number of bytes we can hide in the WAV file using LSB.
    Each audio byte can hide 1 bit => capacity in bytes = num_audio_bytes // 8.
    """
    with wave.open(wav_path, "rb") as wf:
        frames = wf.readframes(wf.getnframes())
        return len(frames) // 8


# Function: hide data (with header) into WAV using LSB
def hide_bytes_in_wav(input_wav: str, output_wav: str, payload_bytes: bytes, progress_callback=None):
    """
    Embed payload_bytes into input_wav LSB and write to output_wav.
    payload_bytes should already include header (magic + salt + length + encrypted_data).
    """
    with wave.open(input_wav, "rb") as src:
        params = src.getparams()
        frames = bytearray(src.readframes(src.getnframes()))

    total_bits = len(payload_bytes) * 8
    capacity_bits = len(frames)
    if total_bits > capacity_bits:
        raise ValueError("Payload too large for this audio file.")

    # Convert payload to bit string
    bits = ''.join(format(b, '08b') for b in payload_bytes)

    # Embed bits into LSB of frames
    for i, bit in enumerate(bits):
        frames[i] = (frames[i] & 0xFE) | int(bit)
        if progress_callback and (i % 5000 == 0):
            progress_callback(i / total_bits)

    # Write modified frames to output WAV
    with wave.open(output_wav, "wb") as out:
        out.setparams(params)
        out.writeframes(bytes(frames))

    if progress_callback:
        progress_callback(1.0)


# Function: extract bytes from WAV by reading header then payload
def extract_bytes_from_wav(input_wav: str, progress_callback=None) -> bytes:
    """
    Extract payload bytes from input_wav.
    First reads HEADER_SIZE bytes to obtain magic, salt, and encrypted_length.
    Then reads encrypted_length bytes and returns the encrypted bytes (excluding header).
    """
    with wave.open(input_wav, "rb") as src:
        frames = bytearray(src.readframes(src.getnframes()))

    # Helper to read n bytes from LSB sequentially starting at bit index offset
    def read_n_bytes_from_bits(bit_offset: int, n_bytes: int):
        bits = []
        end_bit = bit_offset + n_bytes * 8
        for i in range(bit_offset, end_bit):
            bits.append(str(frames[i] & 1))
            if progress_callback and (i % 5000 == 0):
                progress_callback((i - bit_offset) / (n_bytes * 8))
        bytes_out = bytearray(int(''.join(bits[i:i+8]), 2) for i in range(0, len(bits), 8))
        return bytes(bytes_out)

    # Read header first
    header_bytes = read_n_bytes_from_bits(0, HEADER_SIZE)
    try:
        magic, salt, enc_len = struct.unpack(HEADER_FMT, header_bytes)
    except Exception as e:
        raise ValueError("Invalid or missing header in audio file.") from e

    if magic != MAGIC:
        raise ValueError("No compatible hidden data found (magic mismatch).")

    # Read encrypted payload bytes after header
    encrypted_bytes = read_n_bytes_from_bits(HEADER_SIZE * 8, enc_len)
    if progress_callback:
        progress_callback(1.0)
    return salt, encrypted_bytes


# ----------------------------- GUI Application -----------------------------
class AudioStegApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Audio Steganography Tool")
        self.geometry("900x560")
        # Allow resizing
        self.minsize(720, 460)

        # Appearance default
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        # State variables
        self.selected_wav_path = None
        self.output_wav_path = None

        # Build UI
        self.build_ui()

    # Function to build UI elements and layout
    def build_ui(self):
        # Top Frame: title and about/clear buttons
        top_frame = ctk.CTkFrame(self)
        top_frame.pack(fill="x", padx=16, pady=(12, 6))

        title_label = ctk.CTkLabel(top_frame, text="Audio Steganography", font=("Arial", 18, "bold"))
        title_label.pack(side="left", padx=(6, 12))

        btn_frame = ctk.CTkFrame(top_frame)
        btn_frame.pack(side="right", padx=6)

        about_btn = ctk.CTkButton(btn_frame, text="About", width=90, command=self.show_about)
        about_btn.grid(row=0, column=0, padx=6)

        clear_btn = ctk.CTkButton(btn_frame, text="Clear Fields", width=110, command=self.clear_fields)
        clear_btn.grid(row=0, column=1, padx=6)

        # Middle: Textbox for message and side file controls
        middle_frame = ctk.CTkFrame(self)
        middle_frame.pack(fill="both", expand=True, padx=16, pady=6)

        # Left: message box
        left_frame = ctk.CTkFrame(middle_frame)
        left_frame.pack(side="left", fill="both", expand=True, padx=(6, 12), pady=6)

        msg_label = ctk.CTkLabel(left_frame, text="Secret Message", font=FONT_NAME)
        msg_label.pack(anchor="w", padx=6, pady=(6, 4))

        self.message_box = ctk.CTkTextbox(left_frame, width=520, height=220, font=FONT_NAME)
        self.message_box.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self.message_box.insert("0.0", "")

        # Right: file selection and controls
        right_frame = ctk.CTkFrame(middle_frame, width=260)
        right_frame.pack(side="right", fill="y", padx=(12, 6), pady=6)

        file_label = ctk.CTkLabel(right_frame, text="Audio File (WAV only)", font=FONT_NAME)
        file_label.pack(anchor="w", padx=8, pady=(8, 4))

        select_btn = ctk.CTkButton(right_frame, text="Select WAV File", command=self.select_wav)
        select_btn.pack(fill="x", padx=8, pady=(0, 8))

        # Label showing selected path
        self.selected_path_label = ctk.CTkLabel(right_frame, text="No file selected", font=FONT_NAME, wraplength=230, anchor="w")
        self.selected_path_label.pack(fill="x", padx=8, pady=(0, 8))

        pass_label = ctk.CTkLabel(right_frame, text="Encryption Password", font=FONT_NAME)
        pass_label.pack(anchor="w", padx=8, pady=(8, 4))

        pw_frame = ctk.CTkFrame(right_frame)
        pw_frame.pack(fill="x", padx=8, pady=(0, 8))

        self.password_entry = ctk.CTkEntry(pw_frame, placeholder_text="Enter password", show="*")
        self.password_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))

        self.show_pw_var = ctk.StringVar(value="0")
        self.show_pw_btn = ctk.CTkButton(pw_frame, text="Show", width=60, command=self.toggle_password)
        self.show_pw_btn.pack(side="right")

        # Buttons for actions
        actions_frame = ctk.CTkFrame(self)
        actions_frame.pack(fill="x", padx=16, pady=(8, 4))

        self.hide_btn = ctk.CTkButton(actions_frame, text="Hide Message", width=160, command=self.on_hide_clicked)
        self.hide_btn.pack(side="left", padx=(20, 12), pady=8)

        self.extract_btn = ctk.CTkButton(actions_frame, text="Extract Message", width=160, command=self.on_extract_clicked)
        self.extract_btn.pack(side="left", padx=12, pady=8)

        # Status label under buttons (single label that changes)
        self.status_label = ctk.CTkLabel(self, text="Status: Ready", font=FONT_NAME, anchor="w")
        self.status_label.pack(fill="x", padx=18, pady=(6, 12))

        # Footer: output path display
        bottom_frame = ctk.CTkFrame(self)
        bottom_frame.pack(fill="x", padx=16, pady=(4, 12))

        self.output_path_label = ctk.CTkLabel(bottom_frame, text="© Esraa Codes", font=FONT_NAME, anchor="w", wraplength=860)
        self.output_path_label.pack(fill="x", padx=6, pady=6)

    # Function: show a simple about popup
    def show_about(self):
        messagebox.showinfo("About", "Audio Steganography Tool\nMade by Esraa Codes")

    # Function: clear input fields and status
    def clear_fields(self):
        self.message_box.delete("0.0", ctk.END)
        self.password_entry.delete(0, ctk.END)
        self.selected_wav_path = None
        self.output_wav_path = None
        self.selected_path_label.configure(text="No file selected")
        self.output_path_label.configure(text="Output: -")
        self.set_status("Ready", "neutral")

    # Function: toggle password visibility
    def toggle_password(self):
        if self.password_entry.cget("show") == "":
            self.password_entry.configure(show="*")
            self.show_pw_btn.configure(text="Show")
        else:
            self.password_entry.configure(show="")
            self.show_pw_btn.configure(text="Hide")

    # Function: update status label (message, type -> success/warning/error/neutral)
    def set_status(self, message: str, status_type: str = "neutral"):
        """
        Update status label text and color. status_type can be: success, warning, error, neutral.
        """
        color_map = {
            "success": ("#1abc9c", "#ffffff"),  # green (text), white background not used
            "warning": ("#f39c12", "#ffffff"),  # orange
            "error": ("#e74c3c", "#ffffff"),    # red
            "neutral": ("#bdc3c7", "#ffffff")   # grey
        }
        fg, _ = color_map.get(status_type, color_map["neutral"])
        self.status_label.configure(text=f"Status: {message}", text_color=fg)

    # Function: open file dialog to select wav file and update label
    def select_wav(self):
        file_path = filedialog.askopenfilename(filetypes=[("WAV audio files", "*.wav")])
        if file_path:
            self.selected_wav_path = file_path
            short = file_path if len(file_path) <= 80 else "..." + file_path[-77:]
            self.selected_path_label.configure(text=f"Selected: {short}")
            self.set_status("WAV file selected", "neutral")
            # compute capacity and show small info
            try:
                capacity = calculate_capacity_bytes(file_path)
                self.set_status(f"Selected. Capacity: {capacity} bytes", "neutral")
            except Exception:
                pass

    # Handler for Hide button click (spawns thread)
    def on_hide_clicked(self):
        if not self.selected_wav_path:
            self.set_status("No WAV file selected", "error")
            return
        message = self.message_box.get("1.0", ctk.END).strip()
        password = self.password_entry.get().strip()
        if not message:
            self.set_status("Message is empty", "error")
            return
        if not password:
            self.set_status("Password is required", "error")
            return

        # Ask where to save
        suggested = os.path.splitext(self.selected_wav_path)[0] + "_steg.wav"
        out_path = filedialog.asksaveasfilename(defaultextension=".wav", initialfile=os.path.basename(suggested),
                                                filetypes=[("WAV audio files", "*.wav")])
        if not out_path:
            self.set_status("Save cancelled", "warning")
            return

        # Run hide in background
        thread = threading.Thread(target=self._hide_task, args=(message, password, out_path), daemon=True)
        thread.start()

    # Background task: encrypt & hide
    def _hide_task(self, message: str, password: str, output_path: str):
        try:
            self.set_status("Encrypting message...", "neutral")
            encrypted_bytes, salt = encrypt_message(password, message)

            # Build header + payload
            payload_len = len(encrypted_bytes)
            header = struct.pack(HEADER_FMT, MAGIC, salt, payload_len)
            payload = header + encrypted_bytes

            # Check capacity
            capacity_bytes = calculate_capacity_bytes(self.selected_wav_path)
            if len(payload) > capacity_bytes:
                self.set_status("Message too large for selected audio", "error")
                return

            # Hide payload
            self.set_status("Hiding data into audio...", "neutral")
            hide_bytes_in_wav(self.selected_wav_path, output_path, payload, progress_callback=self._update_progress)

            self.output_wav_path = output_path
            short = output_path if len(output_path) <= 90 else "..." + output_path[-87:]
            self.output_path_label.configure(text=f"Output: {short}")
            self.set_status("Message hidden successfully", "success")
        except Exception as exc:
            self.set_status(f"Error: {exc}", "error")

    # Small helper to update progress (display as part of status)
    def _update_progress(self, fraction):
        pct = int(fraction * 100)
        self.set_status(f"Working... {pct}%", "neutral")

    # Handler for Extract button click
    def on_extract_clicked(self):
        # Choose file to extract from (allow selecting another file)
        file_path = filedialog.askopenfilename(filetypes=[("WAV audio files", "*.wav")])
        if not file_path:
            self.set_status("Extraction cancelled", "warning")
            return
        # Ask for password
        password = self.password_entry.get().strip()
        if not password:
            self.set_status("Enter password to decrypt", "error")
            return

        # Update selected path label and run background task
        self.selected_wav_path = file_path
        short = file_path if len(file_path) <= 80 else "..." + file_path[-77:]
        self.selected_path_label.configure(text=f"Selected: {short}")

        thread = threading.Thread(target=self._extract_task, args=(file_path, password), daemon=True)
        thread.start()

    # Background task: extract & decrypt
    def _extract_task(self, file_path: str, password: str):
        try:
            self.set_status("Extracting hidden data...", "neutral")
            salt, encrypted_bytes = extract_bytes_from_wav(file_path, progress_callback=self._update_progress)

            self.set_status("Decrypting message...", "neutral")
            try:
                message = decrypt_message(password, encrypted_bytes, salt)
            except Exception as e:
                raise ValueError("Decryption failed: wrong password or corrupted data.") from e

            # Put message into message_box and update status
            self.message_box.delete("0.0", ctk.END)
            self.message_box.insert("0.0", message)
            self.set_status("Message extracted and displayed", "success")
        except Exception as exc:
            self.set_status(f"Error: {exc}", "error")


# ----------------------------- Run App -----------------------------
if __name__ == "__main__":
    app = AudioStegApp()
    app.mainloop()
