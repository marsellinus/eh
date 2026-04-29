# Naskah Demo Teknis (8-12 menit)

Gunakan naskah ini untuk rekaman video atau live demo saat seminar.

## 0:00 - 0:45 | Pembukaan
- Perkenalkan topik, tujuan, dan ruang lingkup riset.
- Jelaskan bahwa pengujian dilakukan pada lingkungan terkontrol untuk ethical hacking.

## 0:45 - 2:00 | Arsitektur Sistem
- Tunjukkan struktur layanan Docker: nginx, ssh-target, fail2ban, crowdsec.
- Jelaskan peran masing-masing komponen.

## 2:00 - 3:30 | Skenario Baseline
- Tunjukkan serangan HTTP flood dan SSH brute force tanpa proteksi.
- Sorot dampak pada log dan hasil attack.

## 3:30 - 5:15 | Skenario Fail2Ban
- Jalankan mode fail2ban.
- Tunjukkan bukti banned IP dan perubahan hasil serangan.
- Sorot detection time dan resource.

## 5:15 - 7:00 | Skenario CrowdSec
- Jalankan mode crowdsec.
- Tunjukkan bukti decision/alert dan blocked IP.
- Bandingkan efektivitas dengan fail2ban.

## 7:00 - 8:30 | Analisis Hasil
- Tampilkan comparison_summary.csv/json.
- Jelaskan 3-4 insight utama: efektivitas blocking, detection latency, CPU/memory.

## 8:30 - 9:30 | Kesimpulan
- Nyatakan solusi terbaik untuk studi kasus ini.
- Jelaskan kapan fail2ban atau crowdsec lebih cocok digunakan.

## 9:30 - 10:00 | Penutup
- Sampaikan limitasi eksperimen.
- Sebutkan rencana pengembangan riset.

## Bukti yang Harus Tampak di Video
- Terminal saat menjalankan benchmark
- Potongan log serangan
- Potongan log blocking/decision
- Ringkasan hasil di folder results
- Slide kesimpulan singkat

## Tips Rekaman
- Resolusi minimal 1280x720
- Audio jelas tanpa noise berat
- Gunakan pointer/highlight saat menunjukkan metrik
- Pastikan durasi sesuai batas yang ditentukan dosen
