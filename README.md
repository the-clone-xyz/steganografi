# 🔒 Program Steganografi GUI (Python + Tkinter)

Ini adalah aplikasi desktop yang dibuat dengan Python dan Tkinter yang memungkinkan pengguna untuk menyisipkan dan mengekstrak pesan rahasia dari dalam gambar. Program ini menggunakan metode **Steganografi LSB (Least Significant Bit)**.

Untuk meningkatkan keamanan, program ini juga mengenkripsi pesan menggunakan **kata sandi** sebelum menyisipkannya ke dalam gambar.

## ✨ Fitur Utama

- **Sisipkan Teks (Encode):** Menyembunyikan pesan teks rahasia ke dalam file gambar (`.png`).
- **Cek Teks (Decode):** Mengekstrak pesan rahasia dari gambar jika kata sandi yang diberikan benar.
- **Bersihkan Gambar (Clean):** Menghapus data tersembunyi dari gambar dengan meng-nol-kan semua _Least Significant Bits_.
- **🔒 Keamanan Enkripsi:** Pesan dienkripsi menggunakan pustaka `cryptography` (Fernet) berbasis kata sandi sebelum disisipkan.
- **🔩 Header Andal:** Menggunakan 4-byte _header_ untuk menyimpan panjang pesan, membuatnya lebih andal daripada penanda akhir.
- **⚡ Antarmuka Responsif:** Menggunakan `threading` untuk menjalankan proses berat (encode, decode) di latar belakang agar GUI tidak "membeku".
- **Log Proses:** Menampilkan log langkah-demi-langkah seperti terminal untuk menunjukkan apa yang sedang dilakukan program (misalnya, "Membuka gambar...", "Mengenkripsi data...", "Menyimpan file...").

## ⚙️ Prasyarat (Instalasi)

Program ini membutuhkan beberapa pustaka Python eksternal. Anda dapat menginstalnya menggunakan `pip`:

```bash
pip install Pillow cryptography
```
