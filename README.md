# ARP-Mass-Poison-

# ARP Mass Poison v5.1 (IPv4 + IPv6 Blackout)

**ARP Mass Poison** adalah script Python untuk melakukan *network disruption* secara masal pada satu atau lebih interface (LAN & Wi-Fi). Script ini menggabungkan **ARP Poisoning**, **IPv6 Router Advertisement (RA) Poisoning**, dan **TCP RST / UDP ICMP Injection** untuk memutus koneksi internet, mematikan video streaming (YouTube/TikTok), memutus pesan (WhatsApp), dan melumpuhkan aplikasi monitoring seperti NetSupport.

Script ini berjalan secara otomatis (auto-detect interface, auto-scan target, auto-detect admin), dan dilengkapi dengan mekanisme *self-protection* agar komputer yang menjalankan script tidak ikut terputus.

---

## Fitur Utama

- **Auto-Detect Interface**: Mendeteksi semua adapter aktif (LAN + Wi-Fi) tanpa perlu input manual.
- **Auto-Target Discovery**: Scan subnet via ARP Request + Passive Sniffing (nangkep device yang baru connect).
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
