# ARP Mass Poison v5.1 (IPv4 + IPv6 Blackout)

**ARP Mass Poison** adalah script Python untuk melakukan *network disruption* secara masal pada satu atau lebih interface (LAN & Wi-Fi). Script ini menggabungkan **ARP Poisoning**, **IPv6 Router Advertisement (RA) Poisoning**, dan **TCP RST / UDP ICMP Injection** untuk memutus koneksi internet, mematikan video streaming (YouTube/TikTok), memutus pesan (WhatsApp), dan melumpuhkan aplikasi monitoring seperti NetSupport.

Script ini berjalan secara otomatis (auto-detect interface, auto-scan target, auto-detect admin), dan dilengkapi dengan mekanisme *self-protection* agar komputer yang menjalankan script tidak ikut terputus.

---

## Fitur Utama

- **Auto-Detect Interface**: Mendeteksi semua adapter aktif (LAN + Wi-Fi) tanpa perlu input manual.
- **Auto-Target Discovery**: Scan subnet via ARP Request + Passive Sniffing (menangkap device yang baru connect).
- **IPv4 Poisoning**: Mengarahkan gateway & target ke MAC address komputer penyerang.
- **IPv6 RA Kill**: Mengirim Router Advertisement (lifetime=0) untuk mematikan rute IPv6 di sisi target, memaksa semua trafik turun ke IPv4 yang sudah di-poison.
- **TCP RST & UDP Killer**: Menangkap paket yang lolos dan langsung mengirim RST (untuk TCP/WA) atau ICMP Port Unreachable (untuk QUIC/YouTube).
- **NetSupport Detection**: Mendeteksi port TCP 5405/5406 (passive sniff + active SYN probe) dan langsung mengisolasi/memutusnya.
- **Self-Protection**: Mengunci MAC gateway asli di ARP cache komputer lokal (`arp -s`) agar PC penyerang tetap online.
- **Drop Mode**: Mematikan IP Forwarding via Registry & netsh agar paket yang lewat langsung dibuang, bukan diteruskan.
- **Fast Restore**: Saat Ctrl+C ditekan, script akan mengirim paket ARP/RA asli secara kilat untuk mengembalikan jaringan seperti semula.

---

## Persyaratan Sistem (Prerequisites)

- **OS**: Windows 10 / 11 (64-bit)
- **Python**: Versi 3.8 atau lebih baru
- **Hak Akses**: Administrator / Root (Wajib)
- **Npcap**: Driver packet capture (Wajib, untuk Scapy)

---

## Instalasi dari 0 (Nol)

### 1. Install Python
1. Download Python dari [python.org](https://www.python.org/downloads/).
2. Saat instalasi, **WAJIB centang** kotak `Add Python to PATH`.
3. Klik `Install Now` dan tunggu selesai.

### 2. Install Npcap
1. Download installer Npcap dari [npcap.com](https://npcap.com/#download).
2. Jalankan installer.
3. Saat instalasi, **WAJIB centang** opsi:
   - `Install Npcap in WinPcap API-compatible Mode`
   - `Support raw 802.11 traffic (and monitor mode)`
4. Selesaikan instalasi.

### 3. Install Library Scapy
Buka Command Prompt (CMD) atau PowerShell, lalu jalankan:
```bash
pip install scapy
```

### 4. Download Script
Simpan script `arp_mass_v5.1.py` di folder yang mudah diakses (misal: `C:\Tools\arp_mass_v5.1.py`). Pastikan file `README.md` ini berada di folder yang sama.

---

## Cara Menjalankan

1. Buka Command Prompt (CMD) atau PowerShell.
2. **WAJIB** jalankan sebagai Administrator (Klik kanan -> *Run as Administrator*).
3. Arahkan ke folder tempat script disimpan:
   ```cmd
   cd /d "C:\Tools"
   ```
4. Jalankan script:
   ```cmd
   python arp_mass_v5.1.py
   ```

---

## Cara Menghentikan & Restore

1. Tekan **Ctrl + C** di jendela CMD tempat script berjalan (cukup SATU KALI).
2. Script akan mendeteksi sinyal, mematikan semua sniffer, dan mengirim paket restore ARP/RA asli.
3. Tunggu hingga muncul tulisan hijau `[+] Network fully restored`.
4. Jaringan akan kembali normal dalam waktu kurang dari 5 detik.

---

## Efek Samping & Dampak (Side Effects)

Karena script ini memutus koneksi secara agresif di layer 2 (Data Link) dan layer 3 (Network), berikut adalah dampak yang akan terjadi pada target:

1. **Internet Mati Total**: Target tidak bisa membuka web, YouTube, TikTok, atau game online.
2. **Aplikasi Pesan Terputus**: WhatsApp, Telegram, atau aplikasi chat lain akan menunjukkan status "Connecting" atau gagal mengirim pesan karena sesi TCP mereka di-reset paksa.
3. **NetSupport & Remote Desktop Terputus**: Segala bentuk remote monitoring atau akses jarak jauh (TeamViewer, NetSupport, RDP) akan terputus karena port mereka diisolasi dan koneksinya di-reset.
4. **Video Buffering**: Video yang sedang diputar di target akan langsung berhenti setelah buffer lokalnya habis.
5. **Disconnect dari Wi-Fi**: Pada beberapa perangkat (terutama Android/iOS), perangkat mungkin otomatis disconnect dari Wi-Fi dan beralih ke Mobile Data (4G/5G) jika fitur *Smart Network Switch* aktif.

> **PERINGATAN:** Script ini tidak memodifikasi konfigurasi permanen pada target. Begitu script dihentikan (`Ctrl+C`), jaringan akan kembali normal. Jika target berpindah ke Mobile Data, memutus koneksinya lewat Wi-Fi tidak akan berpengaruh.

---

## Lisensi & Peringatan Hukum (License & Legal Disclaimer)

**Lisensi**: MIT License (Open Source)

### Disclaimer:
Script ini dibuat dan disediakan **HANYA** untuk tujuan pendidikan, penelitian keamanan jaringan (*Red Teaming/Penetration Testing*), dan uji coba pada jaringan pribadi.

- Penggunaan script ini pada jaringan publik, kantor, sekolah, atau jaringan yang bukan milik Anda tanpa izin tertulis (*authorization*) adalah **TINDAKAN ILEGAL** dan melanggar hukum.
- Penulis script tidak bertanggung jawab atas segala kerusakan, kerugian, atau tuntutan hukum yang timbul akibat penyalahgunaan script ini.
- Anda sepenuhnya bertanggung jawab atas tindakan Anda sendiri.

*Gunakan dengan bijak dan hanya pada jaringan yang Anda miliki atau di mana Anda memiliki izin eksplisit untuk mengujinya.*
