import streamlit as st
import urllib.request
import urllib.parse
import json
import re
import base64
import hashlib
import pandas as pd

st.set_page_config(page_title="White Hat Security & Academy Suite", page_icon="🛡️", layout="wide")

st.title("🛡️ White Hat Security & Academy Suite")
st.caption("Platform edukasi dan toolkit audit keamanan bertahap: Dari konsep dasar hingga analisis tingkat lanjut.")

# Tab Navigation berdasar Level Keahlian
tab_surf1, tab_surf2, tab_surf3, tab_mid1, tab_mid2, tab_deep1, tab_deep2 = st.tabs([
    "🔗 1. URL Safety Check",
    "🏥 2. Web Health Check",
    "🔤 3. Encoder & Hash",
    "🌐 4. Subdomain Recon",
    "📝 5. Password Mutator",
    "🔑 6. JWT Visualizer",
    "📊 7. CVSS Calculator"
])

# ==============================================================================
# LEVEL 1: SURFACE LEVEL (PEMULA / VISUAL)
# ==============================================================================

# --- MODUL 1: URL & LINK SAFETY SCANNER ---
with tab_surf1:
    st.markdown("### 🔗 URL & Link Safety Scanner")
    st.info("💡 **Level Pemula:** Modul ini menganalisis link sebelum Anda mengkliknya untuk mendeteksi penipuan domain (*typosquatting*) atau link pendek yang tersembunyi.")

    url_to_scan = st.text_input("Masukkan Link / URL Target:", value="http://g00gle-login-secure.com/auth", key="input_url_scan")
    
    if st.button("🔍 Periksa Keamanan Link", type="primary", key="btn_url_scan"):
        parsed = urllib.parse.urlparse(url_to_scan.strip())
        domain = parsed.netloc or parsed.path.split('/')[0]
        scheme = parsed.scheme
        
        col_u1, col_u2, col_u3 = st.columns(3)
        with col_u1:
            if scheme == "https":
                st.success("🔒 **Enkripsi HTTPS:** Terpasang")
            else:
                st.warning("⚠️ **HTTPS Tidak Aktif:** Teks biasa (HTTP)")
        
        with col_u2:
            shorteners = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy"]
            if any(s in domain for s in shorteners):
                st.warning("🔗 **Link Pendek:** Tujuan asli tersembunyi")
            else:
                st.success("🌐 **Domain Langsung:** Tidak disingkat")
                
        with col_u3:
            suspicious_keywords = ["login", "verify", "secure", "bank", "account", "update", "free"]
            if any(k in url_to_scan.lower() for k in suspicious_keywords) and not any(legit in domain for legit in ["google.com", "microsoft.com", "github.com"]):
                st.error("🚨 **Indikasi Phishing:** Mengandung kata kunci sensitif")
            else:
                st.info("ℹ️ **Struktur Nama:** Standar")

        st.divider()
        st.markdown("##### 📌 Hasil Analisis Struktur Link:")
        st.write(f"- **Protokol:** `{scheme if scheme else 'http (Default)'}`")
        st.write(f"- **Domain Host:** `{domain}`")
        st.write(f"- **Jalur Halaman (Path):** `{parsed.path}`")

# --- MODUL 2: WEB SECURITY HEALTH CHECK ---
with tab_surf2:
    st.markdown("### 🏥 Web Security Health Check (Skor Simpel)")
    st.info("💡 **Level Pemula:** Memeriksa kesehatan umum situs web dan memberikan nilai kelayakan sederhana (Grade A - F).")

    web_target = st.text_input("Situs Web Target:", value="https://example.com", key="input_health_target")
    use_mock_health = st.checkbox("Gunakan Sample Data Simulasi", key="chk_mock_health")

    if st.button("📊 Cek Kesehatan Situs", type="primary", key="btn_health_check"):
        score = 100
        checks = []

        if use_mock_health:
            checks.append(("Enkripsi HTTPS", "✅ Terpasang", 0))
            checks.append(("HTTP Status", "✅ 200 OK (Normal)", 0))
            checks.append(("Header Keamanan (HSTS/CSP)", "❌ Tidak Lengkap", -30))
            score -= 30
        else:
            try:
                req = urllib.request.Request(web_target, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    headers = dict(resp.headers)
                    status_code = resp.status
                    
                if web_target.startswith("https"):
                    checks.append(("Enkripsi HTTPS", "✅ Terpasang", 0))
                else:
                    checks.append(("Enkripsi HTTPS", "❌ Tidak Menggunakan HTTPS", -40))
                    score -= 40
                    
                checks.append(("HTTP Status Code", f"✅ {status_code} OK", 0))
                
                # Cek Header Sederhana
                if "strict-transport-security" in [h.lower() for h in headers.keys()]:
                    checks.append(("Perlindungan HSTS", "✅ Aktif", 0))
                else:
                    checks.append(("Perlindungan HSTS", "⚠️ Tidak Ditemukan", -20))
                    score -= 20
            except Exception as e:
                st.error(f"Gagal memeriksa situs: {e}")
                score = 0

        # Menentukan Grade
        if score >= 90: grade, color = "A+", "green"
        elif score >= 75: grade, color = "B", "blue"
        elif score >= 50: grade, color = "C", "orange"
        else: grade, color = "F (Rentan)", "red"

        col_g1, col_g2 = st.columns([1, 2])
        with col_g1:
            st.metric("Skor Keamanan", f"{score} / 100")
            st.markdown(f"### Grade Web: :{color}[{grade}]")
        with col_g2:
            st.dataframe(pd.DataFrame(checks, columns=["Parameter", "Hasil Check", "Penalti Skor"]), use_container_width=True)

# --- MODUL 3: ENCODER & HASH PLAYGROUND ---
with tab_surf3:
    st.markdown("### 🔤 Encoder & Hash Playground")
    st.info("💡 **Level Pemula:** Uji coba bagaimana teks biasa diubah menjadi format sandi (Base64) atau identitas unik (*Hash*) yang tidak bisa dibalikkan.")

    input_text = st.text_input("Teks Uji Coba:", value="Rahasia123", key="input_play_text")
    
    col_enc1, col_enc2 = st.columns(2)
    with col_enc1:
        st.markdown("##### 🔄 Format Encoding (Dapat Didekode)")
        b64_enc = base64.b64encode(input_text.encode()).decode()
        url_enc = urllib.parse.quote(input_text)
        st.text_input("Base64 Encoding:", value=b64_enc, disabled=True)
        st.text_input("URL Encoding:", value=url_enc, disabled=True)
        
    with col_enc2:
        st.markdown("##### 🔒 Hashing Kriptografi (Satu Arah)")
        md5_hash = hashlib.md5(input_text.encode()).hexdigest()
        sha256_hash = hashlib.sha256(input_text.encode()).hexdigest()
        st.text_input("MD5 Hash (32 char):", value=md5_hash, disabled=True)
        st.text_input("SHA-256 Hash (64 char):", value=sha256_hash, disabled=True)

# ==============================================================================
# LEVEL 2: MID-WATER LEVEL (MENENGAH)
# ==============================================================================

# --- MODUL 4: PASSIVE SUBDOMAIN FINDER ---
with tab_mid1:
    st.markdown("### 🌐 Passive Subdomain & Footprint Finder")
    st.info("💡 **Level Menengah:** Mencari jejak cabang domain (*subdomain*) target melalui catatan publik tanpa menyerang server target.")

    use_sample_sub = st.checkbox("Gunakan Data Simulasi Subdomain", key="chk_sub_mid")
    domain_input = st.text_input("Domain Utama Target:", value="example.com", key="input_sub_domain")

    if st.button("🔍 Cari Subdomain Pasif", type="primary", key="btn_sub_search"):
        subdomains = set()
        if use_sample_sub:
            subdomains = {"admin.example.com", "api.example.com", "mail.example.com", "dev.example.com", "staging.example.com"}
        else:
            try:
                url = f"https://crt.sh/?q=%.{domain_input.strip()}&output=json"
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    data = json.loads(resp.read().decode())
                    for entry in data:
                        for sub in entry.get('name_value', '').split('\n'):
                            if domain_input.strip() in sub:
                                subdomains.add(sub.strip().lower())
            except Exception as e:
                st.error(f"Gagal mengambil data pasif: {e}")

        if subdomains:
            st.success(f"Ditemukan **{len(subdomains)}** subdomain terdaftar.")
            st.dataframe(pd.DataFrame(sorted(list(subdomains)), columns=["Subdomain Target"]), use_container_width=True)

# --- MODUL 5: PASSWORD MUTATOR ---
with tab_mid2:
    st.markdown("### 📝 Password Policy & Mutator")
    st.info("💡 **Level Menengah:** Melihat bagaimana hacker memvariasikan satu kata dasar untuk menebak kata sandi pengguna (*dictionary attack*).")

    base_word = st.text_input("Kata Kunci Dasar (misal nama produk/perusahaan):", value="Admin2026", key="input_mut_word")

    if st.button("⚡ Simulasikan Variasi Password", type="primary", key="btn_mut_gen"):
        w = base_word.strip()
        mutations = set([
            w, w.lower(), w.upper(), w.capitalize(),
            w + "123", w + "!", "123" + w,
            w.replace('a', '@').replace('i', '1').replace('e', '3').replace('o', '0')
        ])
        st.success(f"Dihasilkan **{len(mutations)}** variasi kombinasi umum:")
        st.text_area("Kumpulan Kombinasi:", value="\n".join(sorted(list(mutations))), height=160)

# ==============================================================================
# LEVEL 3: DEEP WATER LEVEL (LANJUTAN / AUDIT)
# ==============================================================================

# --- MODUL 6: JWT INSPECTOR ---
with tab_deep1:
    st.markdown("### 🔑 JWT Security & Structure Inspector")
    st.info("💡 **Level Lanjutan:** Membongkar token *login* aplikasi modern (*JSON Web Token*) untuk menginspeksi hak akses dan algoritma enkripsinya.")

    jwt_input = st.text_area("Masukkan JWT Token:", value="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIiwicm9sZSI6ImFkbWluIn0.signature", key="input_jwt_deep")

    if st.button("🔓 Dekode & Evaluasi JWT", type="primary", key="btn_jwt_eval"):
        parts = jwt_input.strip().split('.')
        if len(parts) != 3:
            st.error("Format JWT tidak valid (harus terdiri dari 3 bagian terpisah titik).")
        else:
            try:
                def pad_b64(data): return data + '=' * (-len(data) % 4)
                header = json.loads(base64.urlsafe_b64decode(pad_b64(parts[0])))
                payload = json.loads(base64.urlsafe_b64decode(pad_b64(parts[1])))
                
                col_j1, col_j2 = st.columns(2)
                with col_j1:
                    st.markdown("**Header (Algoritma Token):**")
                    st.json(header)
                with col_j2:
                    st.markdown("**Payload (Data & Hak Akses):**")
                    st.json(payload)
                    
                if header.get("alg") == "none":
                    st.error("🚨 **RISIKO KRITIS:** Token menggunakan `alg: none` (Dapat dimanipulasi tanpa verifikasi)!")
                else:
                    st.info(f"ℹ️ Token menggunakan algoritma proteksi: **{header.get('alg')}**")
            except Exception as e:
                st.error(f"Gagal mendekode token: {e}")

# --- MODUL 7: CVSS CALCULATOR ---
with tab_deep2:
    st.markdown("### 📊 CVSS v3.1 Severity Rating Calculator")
    st.info("💡 **Level Lanjutan:** Kalkulator standar industri untuk menentukan tingkat keparahan risiko dari celah keamanan yang ditemukan.")

    col_c1, col_c2 = st.columns(2)
    with col_c1:
        av = st.selectbox("Attack Vector (Jalur Serangan):", ["Network (Jaringan)", "Adjacent (Jaringan Lokal)", "Local (Akses Fisik/Lokal)"])
        ac = st.selectbox("Attack Complexity (Tingkat Kesulitan):", ["Low (Mudah)", "High (Sangat Sulit)"])
    with col_c2:
        pr = st.selectbox("Privileges Required (Akses Dibutuhkan):", ["None (Tanpa Login)", "Low (User Biasa)", "High (Admin)"])
        c_imp = st.selectbox("Dampak Kerahasiaan Data (Confidentiality):", ["High (Bocor Total)", "Low (Bocor Sebagian)", "None (Tidak Ada)"])

    score = 0.0
    if "Network" in av: score += 4.0
    else: score += 2.0
    if "Low" in ac: score += 2.0
    if "None" in pr: score += 2.5
    if "High" in c_imp: score += 1.5
    
    final_score = min(round(score, 1), 10.0)

    st.divider()
    if final_score >= 9.0: st.error(f"🚨 **Skor CVSS: {final_score} / 10.0 (CRITICAL)**")
    elif final_score >= 7.0: st.warning(f"⚠️ **Skor CVSS: {final_score} / 10.0 (HIGH)**")
    elif final_score >= 4.0: st.info(f"ℹ️ **Skor CVSS: {final_score} / 10.0 (MEDIUM)**")
    else: st.success(f"✅ **Skor CVSS: {final_score} / 10.0 (LOW)**")
