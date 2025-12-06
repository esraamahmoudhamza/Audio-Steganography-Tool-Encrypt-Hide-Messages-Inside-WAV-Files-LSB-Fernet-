# Audio Steganography Tool

A lightweight and user-friendly **audio steganography application** built with **Python**, **CustomTkinter**, and **Fernet encryption**.  
This tool allows you to securely **encrypt text messages** and hide them inside **WAV audio files** using **LSB (Least Significant Bit) steganography**.

---

## 🚀 Features
- 🔐 **Strong Encryption** using PBKDF2-HMAC-SHA256 + Fernet.
- 🎧 **LSB Audio Steganography** for hiding encrypted payloads inside WAV files.
- 📦 **Custom Header Format:**
  ```
  magic (4 bytes) + salt (16 bytes) + encrypted_length (8 bytes)
  ```
- 🧠 Automatic capacity detection before embedding.
- 🖥️ Modern GUI built with CustomTkinter:
  - Message textbox  
  - File picker  
  - Output file path preview  
  - Show/Hide password toggle  
  - Status messages  
  - Clear Fields button  
  - Extracted text shown directly in the UI  

---

## 🛠️ How It Works
1. You enter a message + password.  
2. The tool encrypts the message using a derived key (PBKDF2).  
3. It embeds the encrypted bytes inside the WAV file using LSB.  
4. During extraction, the tool reads the header, extracts the encrypted data, and decrypts it back to text.

---

## 📦 Requirements
Install dependencies:
```bash
pip install customtkinter cryptography
```

---

## ▶️ Usage
1. Launch the application  
2. Enter your secret message  
3. Choose a WAV file  
4. Enter password  
5. Click **Hide Message** to generate a stego-audio file  

To extract:
1. Load the WAV file containing hidden data  
2. Enter password  
3. Click **Extract Message**

---

## 📚 Technologies Used
- Python  
- CustomTkinter  
- cryptography (Fernet, PBKDF2-HMAC-SHA256)  
- LSB audio steganography  
- Wave module + struct  

---

## 🔗 Follow Me

Stay connected for more cool projects & tutorials 🚀

* 📸 [Instagram](https://www.instagram.com/esraa_codes)
* 🎵 [TikTok](https://www.tiktok.com/@esraa.codes)
* ▶️ [YouTube](https://www.youtube.com/@EsraaCodes)
* 🌐 [GitHub](https://github.com/esraamahmoudhamza)


## ⭐ Support

If you like this project:
⭐ **Star the repo** — it helps a lot!
📢 **Share it** with friends & devs
📺 **Subscribe** on YouTube for more awesome builds 🚀
