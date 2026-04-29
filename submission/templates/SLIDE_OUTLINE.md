# Outline Slide Presentasi

Gunakan 10-12 slide dengan durasi presentasi 10-15 menit.

## Slide 1 - Judul
- Analisis Komparatif CrowdSec vs Fail2Ban
- Nama, NIM, Program Studi, Mata Kuliah
- Dosen pengampu

## Slide 2 - Latar Belakang
- Ancaman SSH brute force dan HTTP flood pada layanan Docker
- Risiko terhadap availability dan keamanan akses
- Alasan memilih studi kasus ini

## Slide 3 - Rumusan Masalah dan Tujuan
- Rumusan masalah
- Tujuan penelitian
- Batasan eksperimen

## Slide 4 - Arsitektur Eksperimen
- Diagram layanan: nginx, ssh-target, fail2ban/crowdsec
- Topologi jaringan Docker
- Alur logging dan blocking IP

## Slide 5 - Metodologi Ethical Hacking
- Reconnaissance
- Scanning
- Exploitation
- Post-exploitation analysis

## Slide 6 - Skenario Uji
- Mode baseline
- Mode fail2ban
- Mode crowdsec
- Parameter serangan HTTP flood dan SSH brute force

## Slide 7 - Hasil HTTP Flood
- Ringkasan hasil dari attack_http_*.log
- Respons server dan indikasi blocking
- Grafik perbandingan antar mode

## Slide 8 - Hasil SSH Brute Force
- Total attempt, fail, success
- Detection latency dan banned IP
- Insight keamanan dari tiap mode

## Slide 9 - Resource Consumption
- CPU dan memory dari resource_*.csv
- Trade-off proteksi vs efisiensi

## Slide 10 - Analisis Komparatif
- Kelebihan/kekurangan Fail2Ban
- Kelebihan/kekurangan CrowdSec
- Kapan memilih masing-masing

## Slide 11 - Kesimpulan dan Rekomendasi
- Poin kesimpulan utama
- Rekomendasi implementasi defense-in-depth

## Slide 12 - Limitasi dan Future Work
- Keterbatasan eksperimen
- Rencana pengembangan penelitian

## Lampiran (Opsional)
- Screenshot log blocking
- Cuplikan konfigurasi jail/profile
- Link repository dan evidence dataset
