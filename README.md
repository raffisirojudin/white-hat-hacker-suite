# 🛡️ White Hat Security & Academy Suite

**White Hat Security & Academy Suite** adalah aplikasi berbasis Streamlit yang dirancang sebagai media pembelajaran interaktif sekaligus *toolkit* audit keamanan web. Aplikasi ini mengadopsi pendekatan **Pyramid Learning (Iceberg Model)** untuk memandu pengguna dari konsep dasar keamanan hingga analisis teknis tingkat lanjut secara bertahap.

---

## 🚀 Fitur & Modul Utama

Aplikasi ini terdiri dari **10 modul** yang terbagi ke dalam 3 tingkat kesulitan:

### 🌊 Level 1: Surface Level (Pemula & Edukasi Visual)
* **🔗 1. URL Safety Check:** Menganalisis indikasi penipuan domain (*typosquatting*) dan protokol HTTPS.
* **🏥 2. Web Health Check:** Mengukur skor kesehatan umum situs web (Grade A+ hingga F).
* **🔤 3. Encoder & Hash Playground:** Visualisasi konversi teks ke format Base64, URL Encoding, MD5, dan SHA-256.
* **🖼️ 4. EXIF Privacy Inspector:** Membaca metadata file gambar (`.jpg`) untuk mendeteksi potensi kebocoran lokasi GPS dan perangkat.

### 🏊 Level 2: Mid-Water Level (Menengah & Analisis Pasif)
* **🌐 5. Subdomain Recon:** Pengumpulan daftar subdomain pasif memanfaatkan *Certificate Transparency Logs*.
* **📝 6. Password Mutator:** Simulasi variasi kata kunci berbasis *dictionary attack* dan *l33tsp34k*.
* **🤖 7. Robots.txt Recon:** Pemeriksaan lokasi jalur/direktori web yang disembunyikan dari mesin pencari.

### ⚓ Level 3: Deep Water Level (Lanjutan & Audit Spesialis)
* **🔑 8. JWT Inspector:** Pembedahan struktur Header dan Payload pada token otentikasi API (*JSON Web Token*).
* **📊 9. CVSS Calculator:** Kalkulator kalkulasi tingkat keparahan risiko berdasarkan standar internasional CVSS v3.1.
* **🛡️ 10. Log Threat Hunter:** Pendeteksi pola serangan populer (*SQL Injection* & *XSS*) pada berkas log akses server.

---

## 🛠️ Instalasi & Cara Memulai

### 1. Prasyarat
Pastikan Python versi **3.9** atau yang lebih baru sudah terinstal di komputer Anda.

### 2. Kloning Repository
```bash
git clone [https://github.com/USERNAME_ANDA/white-hat-hacker-suite.git](https://github.com/USERNAME_ANDA/white-hat-hacker-suite.git)
cd white-hat-hacker-suite
