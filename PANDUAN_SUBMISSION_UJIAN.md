# Panduan Submission Ujian Ethical Hacking

Dokumen ini memetakan kebutuhan output ujian ke artefak yang sudah ada di repository, sekaligus daftar gap yang perlu dilengkapi sebelum submit.

## 1) Status Kelengkapan Output Wajib

| Output Wajib | Status Saat Ini | Bukti di Repository | Aksi Lanjutan |
|---|---|---|---|
| Laporan / Technical Report (PDF) | Belum final PDF | `LAPORAN_PENELITIAN_ETHICAL_HACKING.md` | Konversi ke PDF lalu simpan sebagai `submission/01_laporan/Laporan_Ethical_Hacking_Nama_NIM.pdf` |
| Dataset Publik / Experiment Evidence | Sudah tersedia (raw + summary) | folder `results/` dan `logs/` | Rapikan dalam struktur `submission/02_dataset_evidence/` |
| Demonstrasi Teknis (video/live) | Belum ada file video | belum ditemukan file `.mp4/.mkv/.mov/.avi` | Rekam demo 8-12 menit dan simpan `submission/03_demo/Demo_Teknis_Nama_NIM.mp4` |
| Slide Presentasi | Belum ada file slide | belum ditemukan file `.ppt/.pptx/.odp` | Buat slide dari outline `submission/templates/SLIDE_OUTLINE.md` |
| Poster Ilmiah | Belum ada file poster | belum ditemukan file poster `.pdf/.png` | Buat poster dari outline `submission/templates/POSTER_OUTLINE.md` |

## 2) Struktur Folder Submission yang Disarankan

Gunakan struktur berikut agar reviewer mudah memverifikasi kelengkapan:

```text
submission/
  01_laporan/
    Laporan_Ethical_Hacking_Nama_NIM.pdf
  02_dataset_evidence/
    results/
    logs/
    README_dataset.md
  03_demo/
    Demo_Teknis_Nama_NIM.mp4
    SCRIPT_DEMO.md
  04_slide/
    Presentasi_Ethical_Hacking_Nama_NIM.pptx
  05_poster/
    Poster_Ilmiah_Ethical_Hacking_Nama_NIM.pdf
```

## 3) Checklist Mutu Akademik (Anti-Plagiarisme)

- [ ] Topik dan studi kasus jelas: komparasi CrowdSec vs Fail2Ban pada Docker home server.
- [ ] Semua screenshot/grafik berasal dari eksperimen sendiri.
- [ ] Penjelasan metodologi konsisten dengan implementasi pada folder `scripts/`.
- [ ] Data pada kesimpulan konsisten dengan `results/comparison_summary.csv` dan `results/comparison_summary.json`.
- [ ] Daftar pustaka menggunakan format sitasi yang konsisten (misal IEEE).
- [ ] Slide, poster, dan video menggunakan narasi yang sama dengan laporan.

## 4) Dataset / Evidence Minimal yang Harus Dibawa

Wajib sertakan minimal item berikut:

- `results/comparison_summary.csv`
- `results/comparison_summary.json`
- `results/attack_http_baseline.log`
- `results/attack_http_fail2ban.log`
- `results/attack_http_crowdsec.log`
- `results/attack_ssh_baseline.log`
- `results/attack_ssh_fail2ban.log`
- `results/attack_ssh_crowdsec.log`
- `results/resource_baseline.csv`
- `results/resource_fail2ban.csv`
- `results/resource_crowdsec.csv`
- `results/security_snapshot_baseline.json`
- `results/security_snapshot_fail2ban.json`
- `results/security_snapshot_crowdsec.json`

## 5) Alur Presentasi Seminar (Ringkas)

1. Latar belakang dan ancaman nyata SSH brute force + HTTP flood.
2. Arsitektur eksperimen Docker dan skenario baseline/fail2ban/crowdsec.
3. Metodologi ethical hacking (recon, scanning, exploitation, post-exploitation).
4. Hasil kuantitatif utama (efektivitas blocking, detection time, CPU/memory).
5. Analisis trade-off dan rekomendasi implementasi.
6. Penutup: kontribusi, limitasi, dan rencana riset lanjutan.

## 6) Catatan Penting Sebelum Submit

- Pastikan metadata nama/NIM sudah tertulis pada laporan, slide, poster, dan video.
- Simpan semua output akhir ke folder `submission/` agar mudah diarsipkan.
- Gunakan nama file konsisten dan profesional.
