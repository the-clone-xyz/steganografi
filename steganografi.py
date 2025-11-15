from PIL import Image

def text_to_binary(text):
    """Mengubah string teks menjadi string biner."""
    binary = ''.join(format(ord(char), '08b') for char in text)
    return binary

def binary_to_text(binary):
    """MengUbah string biner kembali menjadi string teks."""
    text = ""
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        if len(byte) == 8:
            text += chr(int(byte, 2))
    return text

def encode_image(image_path, secret_text, output_path):
    """Fitur 1: Menyisipkan teks ke dalam gambar."""
    try:
        img = Image.open(image_path)
    except IOError:
        print(f"Error: Tidak dapat membuka gambar di {image_path}")
        return

    # Tambahkan delimiter unik untuk menandai akhir pesan
    secret_text += "_END_"
    binary_secret = text_to_binary(secret_text)
    
    data_index = 0
    img_data = list(img.getdata())
    
    # Cek kapasitas
    max_bits = len(img_data) * 3 # 3 channel (R, G, B) per piksel
    if len(binary_secret) > max_bits:
        print(f"Error: Teks terlalu panjang untuk disisipkan di gambar ini.")
        print(f"Kapasitas maks: {max_bits // 8} bytes. Ukuran pesan: {len(binary_secret) // 8} bytes.")
        return

    new_img_data = []
    
    for pixel in img_data:
        # Ubah pixel tuple menjadi list agar bisa dimodifikasi
        new_pixel = list(pixel)

        for i in range(3): # Loop untuk R, G, B
            if data_index < len(binary_secret):
                # Ubah LSB (Least Significant Bit) dari channel warna
                # & 254 (11111110) untuk meng-nol-kan LSB
                # | int(bit) untuk mengatur LSB baru
                new_pixel[i] = (pixel[i] & 254) | int(binary_secret[data_index])
                data_index += 1
            
        new_img_data.append(tuple(new_pixel))

    # Buat gambar baru dengan data yang sudah dimodifikasi
    new_img = Image.new(img.mode, img.size)
    new_img.putdata(new_img_data)
    new_img.save(output_path)
    print(f"Sukses! Teks tersembunyi telah disisipkan ke dalam {output_path}")

def decode_image(image_path):
    """Fitur 2: Mengecek dan mengekstrak teks tersembunyi."""
    try:
        img = Image.open(image_path)
    except IOError:
        print(f"Error: Tidak dapat membuka gambar di {image_path}")
        return

    binary_data = ""
    img_data = list(img.getdata())

    for pixel in img_data:
        for i in range(3): # Loop untuk R, G, B
            # Ekstrak LSB (bit terakhir)
            binary_data += str(pixel[i] % 2)

    # Cari delimiter "_END_" dalam data biner
    delimiter_binary = text_to_binary("_END_")
    delimiter_index = binary_data.find(delimiter_binary)

    if delimiter_index != -1:
        # Jika delimiter ditemukan, potong data biner dan ubah ke teks
        secret_binary = binary_data[:delimiter_index]
        secret_text = binary_to_text(secret_binary)
        if secret_text:
            print(f"Ditemukan teks tersembunyi:")
            print("---------------------------------")
            print(secret_text)
            print("---------------------------------")
            return secret_text
        else:
            print("Gambar ini sepertinya memiliki sisa data, tapi tidak terdeteksi sebagai teks valid.")
            return None
    else:
        print("Tidak ada teks tersembunyi yang terdeteksi (atau formatnya tidak dikenal).")
        return None

def clean_image(image_path, output_path):
    """Fitur 3: Membersihkan gambar dari teks tersembunyi (metode LSB)."""
    try:
        img = Image.open(image_path)
    except IOError:
        print(f"Error: Tidak dapat membuka gambar di {image_path}")
        return

    img_data = list(img.getdata())
    new_img_data = []

    for pixel in img_data:
        new_pixel = list(pixel)
        for i in range(3): # Loop untuk R, G, B
            # Bersihkan LSB dengan meng-nol-kannya
            # Bitwise AND dengan 254 (11111110)
            new_pixel[i] = new_pixel[i] & 254
        
        new_img_data.append(tuple(new_pixel))

    # Buat gambar baru dengan LSB yang sudah bersih
    new_img = Image.new(img.mode, img.size)
    new_img.putdata(new_img_data)
    new_img.save(output_path)
    print(f"Sukses! Gambar telah dibersihkan dan disimpan di {output_path}")

# --- Contoh Penggunaan ---
if __name__ == "__main__":
    
    # Sediakan gambar Anda sendiri, pastikan dalam format lossless seperti .png
    # Format .jpg tidak disarankan karena kompresinya akan merusak data LSB
    INPUT_IMAGE = "gambar_asli.png" 
    ENCODED_IMAGE = "gambar_terenkripsi.png"
    CLEANED_IMAGE = "gambar_bersih.png"

    # -----------------------------------------------
    # 1. MENYISIPKAN TEKS
    # -----------------------------------------------
    print("### FITUR 1: MENYISIPKAN TEKS ###")
    # Buat gambar dummy jika tidak ada
    try:
        Image.open(INPUT_IMAGE)
    except FileNotFoundError:
        print(f"Membuat gambar dummy '{INPUT_IMAGE}'...")
        dummy_img = Image.new('RGB', (100, 100), color = 'white')
        dummy_img.save(INPUT_IMAGE)
        
    pesan_rahasia = "Ini adalah pesan rahasia saya yang akan disembunyikan. Semoga tidak ada yang tahu!"
    encode_image(INPUT_IMAGE, pesan_rahasia, ENCODED_IMAGE)

    print("\n" + "="*40 + "\n")

    # -----------------------------------------------
    # 2. MENGECEK GAMBAR
    # -----------------------------------------------
    print("### FITUR 2: MENGECEK TEKS TERSEMBUNYI ###")
    print(f"Mengecek gambar {ENCODED_IMAGE}...")
    decode_image(ENCODED_IMAGE)
    
    print("\nMengecek gambar asli (seharusnya tidak ada pesan)...")
    decode_image(INPUT_IMAGE)

    print("\n" + "="*40 + "\n")

    # -----------------------------------------------
    # 3. MEMBERSIHKAN TEKS
    # -----------------------------------------------
    print("### FITUR 3: MEMBERSIHKAN GAMBAR ###")
    clean_image(ENCODED_IMAGE, CLEANED_IMAGE)
    
    print("\nMengecek gambar yang sudah dibersihkan (seharusnya tidak ada pesan)...")
    decode_image(CLEANED_IMAGE)