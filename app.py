import streamlit as st
import urllib.request
import json
import re
import base64
import pandas as pd
from PIL import Image

st.set_page_config(page_title="White Hat Security Audit Suite", page_icon="🛡️", layout="wide")

st.title("🛡️ White Hat Security Audit & Assessment Suite")
st.caption("Toolkit audit keamanan jaringan, konfigurasi web, dan analisis otentikasi untuk pengujian berizin.")

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "🌐 1. Passive Subdomain Finder",
    "🛡️ 2. Security Headers & CORS",
    "🔑 3. JWT Inspector",
    "📝 4. Password Policy Wordlist",
    "🖼️ 5. Steganography LSB",
    "📊 6. CVSS v3.1 Calculator"
])

# ==============================================================================
# MODUL 1: PASSIVE SUBDOMAIN FINDER (crt.sh API)
# ==============================================================================
with tab1:
    st.markdown("### 🌐 Passive Subdomain Finder")
    st.write("Mengumpulkan informasi subdomain terdaftar melalui Certificate Transparency Logs secara pasif.")
    
    use_sample_sub = st.checkbox("Gunakan Sample Target Simulasi", key="chk_sub")
    domain_input = st.text_input("Domain Target (contoh: example.com):", value="example.com", key="input_domain")
    
    if st.button("🔍 Cari Subdomain", type="primary", key="btn_sub"):
        subdomains = set()
        if use_sample_sub:
            subdomains = {"admin.example.com", "api.example.com", "mail.example.com", "dev.example.com", "vpn.example.com"}
        else:
            try:
                url = f"https://crt.sh/?q=%.{domain_input.strip()}&output=json"
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read().decode())
                    for entry in data:
                        name = entry.get('name_value', '')
                        for sub in name.split('\n'):
                            if domain_input.strip() in sub:
                                subdomains.add(sub.strip().lower())
            except Exception as e:
                st.error(f"Gagal mengambil data dari crt.sh: {e}")
        
        if subdomains:
            st.success(f"Ditemukan **{len(subdomains)}** subdomain unik.")
            st.dataframe(pd.DataFrame(sorted(list(subdomains)), columns=["Subdomain"]), use_container_width=True)

# ==============================================================================
# MODUL 2: SECURITY HEADERS & CORS AUDITOR
# ==============================================================================
with tab2:
    st.markdown("### 🛡️ Security Headers & CORS Auditor")
    st.write("Memeriksa kelengkapan HTTP Security Headers dan konfigurasi awal CORS.")
    
    target_url = st.text_input("URL Web Target:", value="https://example.com", key="input_url_sec")
    
    if st.button("🔍 Audit Header", type="primary", key="btn_headers"):
        try:
            req = urllib.request.Request(target_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                headers = dict(resp.headers)
                
            important_headers = {
                "Strict-Transport-Security": "HSTS (Proteksi HTTPS)",
                "Content-Security-Policy": "CSP (Proteksi XSS/Injection)",
                "X-Frame-Options": "Clickjacking Protection",
                "X-Content-Type-Options": "MIME-Sniffing Protection",
                "Access-Control-Allow-Origin": "CORS Policy"
            }
            
            results = []
            for h, desc in important_headers.items():
                val = headers.get(h) or headers.get(h.lower())
                status = "✅ Diterapkan" if val else "❌ Tidak Ada"
                results.append({"Security Header": h, "Fungsi": desc, "Status": status, "Value": val if val else "-"})
                
            st.dataframe(pd.DataFrame(results), use_container_width=True)
        except Exception as e:
            st.error(f"Gagal memeriksa URL: {e}")

# ==============================================================================
# MODUL 3: JWT SECURITY INSPECTOR
# ==============================================================================
with tab3:
    st.markdown("### 🔑 JWT Security & Structure Inspector")
    st.write("Dekode struktur JSON Web Token (JWT) untuk menganalisis klaim dan algoritma enkripsi.")
    
    jwt_input = st.text_area("Masukkan JWT Token:", value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", key="input_jwt")
    
    if st.button("🔓 Dekode JWT", type="primary", key="btn_jwt"):
        parts = jwt_input.strip().split('.')
        if len(parts) != 3:
            st.error("Format JWT tidak valid (harus 3 bagian yang dipisahkan titik).")
        else:
            try:
                def pad_b64(data):
                    return data + '=' * (-len(data) % 4)

                header = json.loads(base64.urlsafe_b64decode(pad_b64(parts[0])))
                payload = json.loads(base64.urlsafe_b64decode(pad_b64(parts[1])))
                
                col_j1, col_j2 = st.columns(2)
                with col_j1:
                    st.markdown("**Header (Algoritma & Tipe):**")
                    st.json(header)
                with col_j2:
                    st.markdown("**Payload (Klaim & Data):**")
                    st.json(payload)
                    
                if header.get("alg") == "none":
                    st.error("🚨 WARNING: Token menggunakan algoritma 'none' (sangat rentan bypass otentikasi)!")
                else:
                    st.info(f"ℹ️ Algoritma yang digunakan: **{header.get('alg')}**")
            except Exception as e:
                st.error(f"Gagal mendekode token: {e}")

# ==============================================================================
# MODUL 4: CUSTOM WORDLIST & MUTATION GENERATOR
# ==============================================================================
with tab4:
    st.markdown("### 📝 Password Policy & Wordlist Mutator")
    st.write("Membuat mutasi kata kunci untuk pengujian kekuatan kebijakan password organisasi.")
    
    base_word = st.text_input("Kata Dasar (misal nama perusahaan/layanan):", value="Company2026", key="input_word")
    
    if st.button("⚡ Generate Mutasi Wordlist", type="primary", key="btn_mut"):
        w = base_word.strip()
        mutations = set([
            w, w.lower(), w.upper(), w.capitalize(),
            w + "123", w + "!", "123" + w,
            w.replace('a', '@').replace('i', '1').replace('e', '3').replace('o', '0').replace('s', '$')
        ])
        
        st.success(f"Dihasilkan **{len(mutations)}** variasi wordlist:")
        st.text_area("Hasil Wordlist:", value="\n".join(sorted(list(mutations))), height=150)

# ==============================================================================
# MODUL 5: STEGANOGRAPHY LSB INSPECTOR
# ==============================================================================
with tab5:
    st.markdown("### 🖼️ Steganography LSB Inspector")
    st.write("Inspeksi bit terendah (LSB) pada gambar untuk mendeteksi teks rahasia.")
    
    uploaded_img = st.file_uploader("Unggah Gambar (.png / .bmp):", type=["png", "bmp"], key="stego_img")
    
    if uploaded_img and st.button("🔍 Ekstrak LSB Text", key="btn_stego"):
        try:
            image = Image.open(uploaded_img).convert('RGB')
            pixels = list(image.getdata())
            binary_data = "".join([str(pixel[i] & 1) for pixel in pixels for i in range(3)])
            
            all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
            decoded_chars = []
            for b in all_bytes[:1000]: # Cek 1000 karakter pertama
                char = chr(int(b, 2))
                if 32 <= ord(char) <= 126:
                    decoded_chars.append(char)
                else:
                    break
            
            result_text = "".join(decoded_chars)
            if result_text:
                st.success("Teks terdeteksi pada LSB:")
                st.code(result_text)
            else:
                st.warning("Tidak ditemukan pola teks ASCII yang valid pada LSB awal.")
        except Exception as e:
            st.error(f"Gagal memproses gambar: {e}")

# ==============================================================================
# MODUL 6: CVSS v3.1 CALCULATOR
# ==============================================================================
with tab6:
    st.markdown("### 📊 CVSS v3.1 Severity Rating Calculator")
    st.write("Hitung skor keparahan temuan kerentanan berdasarkan standar CVSS v3.1.")
    
    col_c1, col_c2 = st.columns(2)
    with col_c1:
        av = st.selectbox("Attack Vector (AV)", ["Network (N)", "Adjacent (A)", "Local (L)", "Physical (P)"])
        ac = st.selectbox("Attack Complexity (AC)", ["Low (L)", "High (H)"])
        pr = st.selectbox("Privileges Required (PR)", ["None (N)", "Low (L)", "High (H)"])
    with col_c2:
        ui = st.selectbox("User Interaction (UI)", ["None (N)", "Required (R)"])
        c_imp = st.selectbox("Confidentiality Impact (C)", ["High (H)", "Low (L)", "None (N)"])
        i_imp = st.selectbox("Integrity Impact (I)", ["High (H)", "Low (L)", "None (N)"])
        
    # Estimasi sederhana bobot skor
    score = 0.0
    if "Network" in av: score += 3.5
    elif "Adjacent" in av: score += 2.5
    else: score += 1.5
    
    if "Low" in ac: score += 2.0
    if "None" in pr: score += 2.0
    if "None" in ui: score += 1.5
    if "High" in c_imp: score += 1.0
    if "High" in i_imp: score += 1.0
    
    final_score = min(round(score, 1), 10.0)
    
    st.divider()
    if final_score >= 9.0:
        st.error(f"🚨 **Skor CVSS: {final_score} (CRITICAL)**")
    elif final_score >= 7.0:
        st.warning(f"⚠️ **Skor CVSS: {final_score} (HIGH)**")
    elif final_score >= 4.0:
        st.info(f"ℹ️ **Skor CVSS: {final_score} (MEDIUM)**")
    else:
        st.success(f"✅ **Skor CVSS: {final_score} (LOW)**")
