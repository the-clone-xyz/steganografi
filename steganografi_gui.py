import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog
import os
from PIL import Image
import struct
import threading
import time # Untuk timestamp di log

# Pustaka untuk enkripsi
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

# ===================================================================
# FUNGSI LOGIKA (Tidak ada perubahan di sini dari v4.1/4.2)
# ===================================================================

def derive_key(password: str, salt: bytes = b'salt_') -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=100000, backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_message(message: str, password: str) -> bytes:
    key = derive_key(password)
    f = Fernet(key)
    return f.encrypt(message.encode())

def decrypt_message(token: bytes, password: str) -> str | None:
    try:
        key = derive_key(password)
        f = Fernet(key)
        return f.decrypt(token).decode()
    except InvalidToken:
        return None 
    except Exception:
        return None 

def bytes_to_binary_string(data: bytes) -> str:
    return ''.join(format(byte, '08b') for byte in data)

def binary_string_to_bytes(binary_str: str) -> bytes:
    return bytes(int(binary_str[i:i+8], 2) for i in range(0, len(binary_str), 8))

def gui_encode_image(image_path: str, secret_text: str, password: str, output_path: str, log_callback):
    try:
        log_callback("Membuka gambar sumber...")
        img = Image.open(image_path)
        img = img.convert('RGB')
    except Exception as e:
        raise IOError(f"Gagal membuka gambar: {e}")
    if not password:
        raise ValueError("Kata sandi diperlukan.")
    log_callback("Mengenkripsi pesan...")
    encrypted_message = encrypt_message(secret_text, password)
    message_length = len(encrypted_message)
    length_header = struct.pack('!I', message_length)
    data_to_hide = length_header + encrypted_message
    binary_data_to_hide = bytes_to_binary_string(data_to_hide)
    data_index = 0
    img_data = list(img.getdata())
    max_bits = len(img_data) * 3
    log_callback(f"Ukuran data: {len(binary_data_to_hide)} bits. Kapasitas gambar: {max_bits} bits.")
    if len(binary_data_to_hide) > max_bits:
        raise ValueError(f"Teks terlalu panjang.\nKapasitas maks: {max_bits // 8} bytes.\nUkuran pesan: {len(data_to_hide)} bytes.")
    log_callback("Memulai penyisipan LSB...")
    new_img_data = []
    for pixel in img_data:
        new_pixel = list(pixel)
        for i in range(3):
            if data_index < len(binary_data_to_hide):
                new_pixel[i] = (pixel[i] & 254) | int(binary_data_to_hide[data_index])
                data_index += 1
        new_img_data.append(tuple(new_pixel))
    log_callback("Membuat gambar baru...")
    try:
        new_img = Image.new(img.mode, img.size)
        new_img.putdata(new_img_data)
        log_callback(f"Menyimpan file ke: {output_path}...")
        new_img.save(output_path)
        log_callback("Penyisipan sukses!")
        return True
    except Exception as e:
        raise IOError(f"Gagal menyimpan file: {e}")

def gui_decode_image(image_path: str, password: str, log_callback) -> str | None:
    try:
        log_callback("Membuka gambar untuk pengecekan...")
        img = Image.open(image_path)
        img = img.convert('RGB')
    except Exception as e:
        raise IOError(f"Gagal membuka gambar: {e}")
    if not password:
        raise ValueError("Kata sandi diperlukan.")
    binary_data_extracted = ""
    img_data = list(img.getdata())
    log_callback("Mengekstrak header (32 bits pertama)...")
    header_bits = 32
    for pixel in img_data:
        for i in range(3):
            binary_data_extracted += str(pixel[i] % 2)
            if len(binary_data_extracted) == header_bits: break
        if len(binary_data_extracted) == header_bits: break
    if len(binary_data_extracted) < header_bits:
        log_callback("Gambar terlalu kecil untuk memiliki header. Tidak ada data.")
        return None
    log_callback("Mendekode header untuk ukuran pesan...")
    length_header_bytes = binary_string_to_bytes(binary_data_extracted)
    message_length = struct.unpack('!I', length_header_bytes)[0]
    if message_length == 0:
        log_callback("Header menunjukkan panjang 0. Kemungkinan gambar bersih.")
        return None
    max_bits = len(img_data) * 3
    message_bits = message_length * 8
    total_bits_to_read = header_bits + message_bits
    if total_bits_to_read > max_bits:
        log_callback(f"Header meminta {total_bits_to_read} bits (Pesan: {message_length} bytes).")
        log_callback(f"Kapasitas gambar hanya {max_bits} bits.")
        log_callback("Ini kemungkinan file asli/bersih. Dibatalkan.")
        return None 
    log_callback(f"Header terdeteksi. Ukuran pesan: {message_length} bytes. Total bits akan dibaca: {total_bits_to_read}.")
    binary_data_extracted = ""
    log_callback("Mengekstrak data pesan dari gambar...")
    data_index = 0
    for pixel in img_data:
        for i in range(3):
            binary_data_extracted += str(pixel[i] % 2)
            data_index += 1
            if data_index == total_bits_to_read: break
        if data_index == total_bits_to_read: break
    log_callback("Mengonversi data biner ke bytes...")
    binary_message_data = binary_data_extracted[header_bits:]
    encrypted_message_bytes = binary_string_to_bytes(binary_message_data)
    log_callback("Mencoba mendekripsi data...")
    decrypted_text = decrypt_message(encrypted_message_bytes, password)
    if decrypted_text is None:
        log_callback("Gagal dekripsi. Kata sandi salah atau data rusak.")
        return None
    log_callback("Dekripsi sukses!")
    return decrypted_text

def gui_clean_image(image_path: str, output_path: str, log_callback) -> bool:
    try:
        log_callback(f"Membuka gambar untuk dibersihkan: {image_path}...")
        img = Image.open(image_path)
        img = img.convert('RGB')
    except Exception as e:
        raise IOError(f"Gagal membuka gambar: {e}")
    img_data = list(img.getdata())
    new_img_data = []
    log_callback("Memproses piksel untuk membersihkan LSB (set ke 0)...")
    for pixel in img_data:
        new_pixel = list(pixel)
        for i in range(3):
            new_pixel[i] = new_pixel[i] & 254
        new_img_data.append(tuple(new_pixel))
    try:
        log_callback("Membuat gambar baru yang bersih...")
        new_img = Image.new(img.mode, img.size)
        new_img.putdata(new_img_data)
        log_callback(f"Menyimpan gambar bersih ke: {output_path}...")
        new_img.save(output_path)
        log_callback("Pembersihan sukses!")
        return True
    except Exception as e:
        raise IOError(f"Gagal menyimpan file bersih: {e}")

# ===================================================================
# KELAS APLIKASI GUI (TKINTER) 
# ===================================================================

class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Program Steganografi v4.3.1 (Auto-Input)") # Versi diperbarui
        self.root.geometry("600x750")
        self.root.configure(bg="#f0f0f0")

        self.input_file_path = ""
        self.output_file_path = ""
        self.task_running = False 

        # --- Frame untuk File I/O ---
        file_frame = tk.Frame(root, bg="#f0f0f0", bd=2, relief=tk.GROOVE)
        file_frame.pack(fill="x", padx=10, pady=10)
        self.btn_input = tk.Button(file_frame, text="1. Pilih Gambar Asli", command=self.select_input_file, bg="#ddd")
        self.btn_input.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        self.lbl_input = tk.Label(file_frame, text="File: Belum dipilih", bg="#f0f0f0", wraplength=400)
        self.lbl_input.grid(row=0, column=1, padx=10, pady=10, sticky="w")
        self.btn_output = tk.Button(file_frame, text="2. Tentukan Lokasi Simpan", command=self.select_output_file, bg="#ddd")
        self.btn_output.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
        self.lbl_output = tk.Label(file_frame, text="File: Belum dipilih", bg="#f0f0f0", wraplength=400)
        self.lbl_output.grid(row=1, column=1, padx=10, pady=10, sticky="w")
        file_frame.grid_columnconfigure(1, weight=1)

        # --- Frame untuk Kata Sandi ---
        pass_frame = tk.Frame(root, bg="#f0f0f0", bd=2, relief=tk.GROOVE)
        pass_frame.pack(fill="x", padx=10, pady=(0, 10))
        lbl_pass = tk.Label(pass_frame, text="3. Kata Sandi (WAJIB):", bg="#f0f0f0", font=("Arial", 10, "bold"))
        lbl_pass.pack(side="left", padx=10, pady=10)
        self.password_entry = tk.Entry(pass_frame, show="*", width=40)
        self.password_entry.pack(side="left", fill="x", expand=True, padx=10, pady=10)
        self.show_pass_var = tk.IntVar()
        self.show_pass_check = tk.Checkbutton(pass_frame, text="Lihat", variable=self.show_pass_var, command=self.toggle_password, bg="#f0f0f0")
        self.show_pass_check.pack(side="left", padx=10)

        # --- Frame untuk Teks Rahasia ---
        text_frame = tk.Frame(root, bg="#f0f0f0", bd=2, relief=tk.GROOVE)
        text_frame.pack(fill="x", padx=10, pady=5)
        lbl_text = tk.Label(text_frame, text="4. Masukkan/Lihat Teks Rahasia:", bg="#f0f0f0")
        lbl_text.pack(anchor="w", padx=10, pady=5)
        self.text_area = scrolledtext.ScrolledText(text_frame, wrap=tk.WORD, height=8)
        self.text_area.pack(fill="x", expand=True, padx=10, pady=10)
        
        # --- Frame Tombol Aksi ---
        action_frame = tk.Frame(root, bg="#f0f0f0")
        action_frame.pack(fill="x", padx=10, pady=5)
        self.btn_encode = tk.Button(action_frame, text="Sisipkan Teks", command=self.threaded_encode_action, bg="#4CAF50", fg="white", font=("Arial", 10, "bold"))
        self.btn_encode.pack(side="left", fill="x", expand=True, padx=5, pady=5)
        self.btn_decode = tk.Button(action_frame, text="Cek Teks", command=self.threaded_decode_action, bg="#2196F3", fg="white", font=("Arial", 10, "bold"))
        self.btn_decode.pack(side="left", fill="x", expand=True, padx=5, pady=5)
        
        extra_action_frame = tk.Frame(root, bg="#f0f0f0")
        extra_action_frame.pack(fill="x", padx=10, pady=(0, 10))
        self.btn_clean = tk.Button(extra_action_frame, text="Bersihkan Gambar", command=self.threaded_clean_action, bg="#f44336", fg="white", font=("Arial", 10, "bold"))
        self.btn_clean.pack(side="left", fill="x", expand=True, padx=5, pady=5)
        self.btn_clear_text = tk.Button(extra_action_frame, text="Bersihkan Teks Area", command=self.clear_text_action, bg="#FF9800", fg="white", font=("Arial", 10, "bold"))
        self.btn_clear_text.pack(side="left", fill="x", expand=True, padx=5, pady=5)
        
        # --- Frame LOG TERMINAL ---
        log_frame = tk.Frame(root, bg="#f0f0f0", bd=2, relief=tk.GROOVE)
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)
        lbl_log = tk.Label(log_frame, text="Log Proses:", bg="#f0f0f0")
        lbl_log.pack(anchor="w", padx=10, pady=5)
        self.log_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=10, bg="black", fg="white")
        self.log_area.pack(fill="both", expand=True, padx=10, pady=10)
        self.log_area.config(state="disabled")

        # --- Status Bar ---
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = tk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w", padx=10)
        self.status_bar.pack(side="bottom", fill="x")

        self.buttons = [
            self.btn_input, self.btn_output, self.btn_encode, self.btn_decode,
            self.btn_clean, self.btn_clear_text, self.show_pass_check
        ]

    def toggle_password(self):
        if self.show_pass_var.get(): self.password_entry.config(show="")
        else: self.password_entry.config(show="*")
            
    def update_status(self, message, color="black"):
        self.status_var.set(message)
        self.status_bar.config(fg=color)

    def log_message(self, message):
        self.log_area.config(state="normal")
        timestamp = time.strftime("%H:%M:%S")
        self.log_area.insert("end", f"[{timestamp}] {message}\n")
        self.log_area.see("end")
        self.log_area.config(state="disabled")

    def log_message_safe(self, message):
        self.root.after(0, self.log_message, message)

    def select_input_file(self):
        file_path = filedialog.askopenfilename(
            title="Pilih Gambar Asli",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp"), ("All files", "*.*")]
        )
        if file_path:
            self.input_file_path = file_path
            name = os.path.basename(file_path)
            self.lbl_input.config(text=f"File: {name}")
            self.update_status(f"Gambar asli dipilih: {name}")

    def select_output_file(self):
        input_filename = os.path.basename(self.input_file_path)
        suggested_name = "output.png"
        if input_filename:
            name, _ = os.path.splitext(input_filename)
            suggested_name = f"{name}_output.png"
        file_path = filedialog.asksaveasfilename(
            title="Simpan Gambar Sebagai (WAJIB .png)",
            initialfile=suggested_name, defaultextension=".png",
            filetypes=[("PNG files", "*.png")]
        )
        if file_path:
            if not file_path.lower().endswith('.png'): file_path += '.png'
            self.output_file_path = file_path
            name = os.path.basename(file_path)
            self.lbl_output.config(text=f"File: {name}")
            self.update_status(f"Lokasi simpan diatur: {name}")

    # --- Fungsi Kontrol UI dan Thread ---

    def start_task(self, task_name):
        if self.task_running:
            messagebox.showwarning("Sedang Bekerja", "Tugas lain sedang berjalan. Harap tunggu.")
            return False
            
        self.task_running = True
        for button in self.buttons: button.config(state="disabled")
        
        self.log_area.config(state="normal")
        self.log_area.delete("1.0", "end")
        self.log_area.config(state="disabled")
        
        self.log_message(f"Memulai tugas: {task_name}...")
        self.update_status(f"Menjalankan {task_name}...", "blue")
        return True

    def end_task(self, status_message, color, msg_box=None):
        for button in self.buttons: button.config(state="normal")
        self.update_status(status_message, color)
        self.log_message(f"Tugas Selesai. Status: {status_message}")
        self.task_running = False
        
        if msg_box:
            if msg_box['type'] == 'info':
                messagebox.showinfo(msg_box['title'], msg_box['message'])
            elif msg_box['type'] == 'error':
                messagebox.showerror(msg_box['title'], msg_box['message'])

    # --- Aksi Tombol (Versi Threaded) ---

    def threaded_encode_action(self):
        if not self.start_task("Penyisipan Teks"): return
        
        # --- PERBAIKAN v4.3.1 ADA DI SINI ---
        # Mengganti "1.Selesai"0" kembali ke "1.0"
        if not all([self.input_file_path, self.output_file_path, self.password_entry.get(), self.text_area.get("1.0", "end-1c")]):
        # --- AKHIR PERBAIKAN ---
            
            msg_box = {'type': 'error', 'title': 'Input Kurang', 'message': 'Harap isi Gambar Asli, Lokasi Simpan, Kata Sandi, dan Teks Rahasia.'}
            self.end_task("Gagal: Input tidak lengkap", "red", msg_box)
            return
        if not self.output_file_path.lower().endswith('.png'):
             msg_box = {'type': 'error', 'title': 'Error Tipe File', 'message': 'File output HARUS disimpan sebagai .png.'}
             self.end_task("Gagal: Tipe file output salah", "red", msg_box)
             return
        
        secret_text = self.text_area.get("1.0", "end-1c")
        password = self.password_entry.get()
        
        thread = threading.Thread(
            target=self.run_encode_in_thread, 
            args=(secret_text, password), 
            daemon=True
        )
        thread.start()

    def run_encode_in_thread(self, secret_text, password):
        try:
            gui_encode_image(self.input_file_path, secret_text, password, self.output_file_path, self.log_message_safe)
            self.root.after(0, self.on_encode_complete, None) 
        except Exception as e:
            self.root.after(0, self.on_encode_complete, str(e))

    def on_encode_complete(self, error_message):
        if error_message:
            msg_box = {'type': 'error', 'title': 'Gagal Menyisipkan', 'message': error_message}
            self.end_task(f"Gagal: {error_message}", "red", msg_box)
        else:
            msg = f"Teks berhasil disisipkan!\nFile disimpan di: {self.output_file_path}"
            msg_box = {'type': 'info', 'title': 'Sukses', 'message': msg}
            
            self.input_file_path = self.output_file_path 
            new_filename = os.path.basename(self.input_file_path)
            self.lbl_input.config(text=f"File: {new_filename}") 
            self.log_message_safe(f"Input file sekarang otomatis diatur ke: {new_filename}")

            self.end_task("Sukses: Teks disisipkan!", "green", msg_box)


    def threaded_decode_action(self):
        if not self.start_task("Pengecekan Teks"): return
        if not self.input_file_path:
            msg_box = {'type': 'error', 'title': 'Input Kurang', 'message': 'Silakan pilih Gambar Asli yang ingin dicek.'}
            self.end_task("Gagal: Gambar tidak dipilih", "red", msg_box)
            return
        if not self.password_entry.get():
            msg_box = {'type': 'error', 'title': 'Input Kurang', 'message': 'Silakan masukkan Kata Sandi.'}
            self.end_task("Gagal: Kata sandi kosong", "red", msg_box)
            return
        
        self.text_area.delete("1.0", "end")
        password = self.password_entry.get()
        
        thread = threading.Thread(
            target=self.run_decode_in_thread, 
            args=(password,), 
            daemon=True
        )
        thread.start()

    def run_decode_in_thread(self, password):
        try:
            found_text = gui_decode_image(self.input_file_path, password, self.log_message_safe)
            self.root.after(0, self.on_decode_complete, found_text, None) 
        except Exception as e:
            self.root.after(0, self.on_decode_complete, None, str(e))

    def on_decode_complete(self, found_text, error_message):
        if error_message:
            msg_box = {'type': 'error', 'title': 'Gagal Pengecekan', 'message': error_message}
            self.end_task(f"Gagal: {error_message}", "red", msg_box)
        elif found_text:
            self.text_area.insert("1.0", found_text)
            msg_box = {'type': 'info', 'title': 'Sukses', 'message': 'Teks tersembunyi ditemukan dan ditampilkan.'}
            self.end_task("Sukses: Teks ditemukan!", "green", msg_box)
        else: # found_text is None
            msg_box = {'type': 'info', 'title': 'Info', 'message': 'Tidak ada teks tersembunyi yang ditemukan (atau kata sandi salah).'}
            self.end_task("Info: Teks tidak ditemukan", "black", msg_box)


    def threaded_clean_action(self):
        if not self.start_task("Pembersihan Gambar"): return
        if not self.input_file_path or not self.output_file_path:
            msg_box = {'type': 'error', 'title': 'Input Kurang', 'message': 'Pilih Gambar Asli dan Lokasi Simpan.'}
            self.end_task("Gagal: Input tidak lengkap", "red", msg_box)
            return
        if not self.output_file_path.lower().endswith('.png'):
             msg_box = {'type': 'error', 'title': 'Error Tipe File', 'message': 'File output HARUS disimpan sebagai .png.'}
             self.end_task("Gagal: Tipe file salah", "red", msg_box)
             return

        thread = threading.Thread(
            target=self.run_clean_in_thread, 
            daemon=True
        )
        thread.start()

    def run_clean_in_thread(self):
        try:
            gui_clean_image(self.input_file_path, self.output_file_path, self.log_message_safe)
            self.root.after(0, self.on_clean_complete, None)
        except Exception as e:
            self.root.after(0, self.on_clean_complete, str(e))

    def on_clean_complete(self, error_message):
        if error_message:
            msg_box = {'type': 'error', 'title': 'Gagal Membersihkan', 'message': error_message}
            self.end_task(f"Gagal: {error_message}", "red", msg_box)
        else:
            msg = f"Gambar berhasil dibersihkan!\nFile bersih disimpan di: {self.output_file_path}"
            msg_box = {'type': 'info', 'title': 'Sukses', 'message': msg}
            
            self.input_file_path = self.output_file_path 
            new_filename = os.path.basename(self.input_file_path)
            self.lbl_input.config(text=f"File: {new_filename}") 
            self.log_message_safe(f"Input file sekarang otomatis diatur ke file bersih: {new_filename}")

            self.end_task("Sukses: Gambar dibersihkan!", "green", msg_box)


    def clear_text_action(self):
        self.text_area.delete("1.0", "end")
        self.update_status("Area teks dibersihkan", "black")
        self.log_message("Area teks rahasia dibersihkan.")

# ===================================================================
# MAIN UNTUK MENJALANKAN APLIKASI
# ===================================================================
if __name__ == "__main__":
    main_root = tk.Tk()
    app = SteganographyApp(main_root)
    main_root.mainloop()