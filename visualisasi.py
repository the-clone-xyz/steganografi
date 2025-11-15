import tkinter as tk
from tkinter import ttk

class LSBVisualizerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Visualisasi Cara Kerja LSB")
        self.root.geometry("600x550")
        self.root.configure(bg="#f0f0f0")

        # --- Variabel Kontrol ---
        self.original_value = tk.IntVar(value=150) # Nilai piksel (0-255)
        self.secret_bit = tk.IntVar(value=0)     # Bit rahasia (0 atau 1)

        # --- Frame Input ---
        input_frame = tk.Frame(root, bg="#f0f0f0", bd=2, relief=tk.GROOVE)
        input_frame.pack(fill="x", padx=10, pady=10)

        # 1. Slider untuk Nilai Piksel Asli
        lbl_slider = tk.Label(input_frame, text="Nilai Channel Asli (0-255):", bg="#f0f0f0")
        lbl_slider.pack(pady=(10, 0))
        
        self.slider = ttk.Scale(
            input_frame, 
            from_=0, 
            to=255, 
            orient="horizontal", 
            variable=self.original_value,
            command=self.update_visualization, # Panggil update saat digeser
            length=400
        )
        self.slider.pack(pady=5, padx=20)

        # 2. Radio Button untuk Bit Rahasia
        lbl_bit = tk.Label(input_frame, text="Bit Rahasia yang Ingin Disisipkan:", bg="#f0f0f0")
        lbl_bit.pack(pady=(10, 0))
        
        radio_frame = tk.Frame(input_frame, bg="#f0f0f0")
        radio_frame.pack()
        
        rb_zero = ttk.Radiobutton(
            radio_frame, 
            text="Sisipkan '0'", 
            variable=self.secret_bit, 
            value=0, 
            command=self.update_visualization
        )
        rb_zero.pack(side="left", padx=20, pady=10)
        
        rb_one = ttk.Radiobutton(
            radio_frame, 
            text="Sisipkan '1'", 
            variable=self.secret_bit, 
            value=1, 
            command=self.update_visualization
        )
        rb_one.pack(side="left", padx=20, pady=10)

        # --- Frame Visualisasi Proses ---
        process_frame = tk.Frame(root, bg="#f0f0f0", bd=2, relief=tk.GROOVE)
        process_frame.pack(fill="both", expand=True, padx=10, pady=0)
        
        self.log_area = tk.Text(process_frame, wrap=tk.WORD, height=10, bg="black", fg="#00FF00", font=("Courier New", 12))
        self.log_area.pack(fill="both", expand=True, padx=10, pady=10)
        self.log_area.config(state="disabled")

        # --- Frame Perbandingan Warna ---
        color_frame = tk.Frame(root, bg="#f0f0f0", bd=2, relief=tk.GROOVE)
        color_frame.pack(fill="x", padx=10, pady=10)
        
        lbl_color = tk.Label(color_frame, text="Perbandingan Warna (Asli vs. Stego):", bg="#f0f0f0")
        lbl_color.pack()
        
        self.color_canvas = tk.Canvas(color_frame, width=400, height=50)
        self.color_canvas.pack(pady=10)

        # Panggil update pertama kali untuk mengisi nilai awal
        self.update_visualization()

    def update_visualization(self, event=None):
        """Fungsi inti yang menghitung dan menampilkan visualisasi."""
        
        original_val = self.original_value.get()
        secret_bit = self.secret_bit.get()

        # --- 1. Hitung Proses Penyisipan (Encode) ---
        original_bin = format(original_val, '08b') # Biner 8-bit
        lsb_original = original_bin[-1]
        
        # Proses "membersihkan" LSB
        # (original_val & 254) atau (original_val & 11111110)
        cleared_val = original_val & 254
        cleared_bin = format(cleared_val, '08b')
        
        # Proses "menyisipkan" bit baru
        # (cleared_val | secret_bit)
        new_val = cleared_val | secret_bit
        new_bin = format(new_val, '08b')

        # --- 2. Hitung Proses Pengecekan (Decode) ---
        # (new_val % 2)
        extracted_bit = new_val % 2

        # --- 3. Tampilkan Log Proses ---
        self.log_area.config(state="normal")
        self.log_area.delete("1.0", "end")
        
        log_text = f"--- INPUT ---\n"
        log_text += f"Nilai Channel Asli : {original_val}\n"
        log_text += f"Biner Asli         : {original_bin}  (LSB: {lsb_original})\n"
        log_text += f"Bit Rahasia        : {secret_bit}\n\n"
        
        log_text += f"--- VISUALISASI PENYISIPAN (ENCODE) ---\n"
        log_text += f"1. Nol-kan LSB Asli:\n"
        log_text += f"   {original_bin} ({original_val})\n"
        log_text += f"   & 11111110 (254)\n"
        log_text += f"   = {cleared_bin} ({cleared_val})\n\n"
        
        log_text += f"2. Sisipkan Bit Rahasia:\n"
        log_text += f"   {cleared_bin} ({cleared_val})\n"
        log_text += f"   | 0000000{secret_bit} ({secret_bit})\n"
        log_text += f"   = {new_bin} ({new_val})\n\n"
        
        log_text += f"--- VISUALISASI PENGECEKAN (DECODE) ---\n"
        log_text += f"1. Ambil LSB dari Nilai Baru:\n"
        log_text += f"   {new_bin} ({new_val}) % 2\n"
        log_text += f"   = {extracted_bit}\n"
        
        self.log_area.insert("1.0", log_text)
        self.log_area.config(state="disabled")

        # --- 4. Tampilkan Perbandingan Warna ---
        # Kita buat warna 'dummy' di mana hanya nilai R yang berubah
        # G dan B kita set ke 100 agar terlihat jelas
        
        # Konversi nilai RGB (0-255) ke format hex (#RRGGBB)
        original_hex = f"#{original_val:02x}6464" # (R, 100, 100)
        new_hex = f"#{new_val:02x}6464"        # (R_baru, 100, 100)
        
        self.color_canvas.delete("all") # Hapus kotak lama
        
        # Kotak Warna Asli
        self.color_canvas.create_rectangle(50, 5, 200, 45, fill=original_hex, outline="black")
        self.color_canvas.create_text(125, 25, text=f"ASLI\n({original_val}, 100, 100)", fill="white")
        
        # Kotak Warna Stego (Baru)
        self.color_canvas.create_rectangle(210, 5, 360, 45, fill=new_hex, outline="black")
        self.color_canvas.create_text(285, 25, text=f"STEGO\n({new_val}, 100, 100)", fill="white")

if __name__ == "__main__":
    main_root = tk.Tk()
    app = LSBVisualizerApp(main_root)
    main_root.mainloop()