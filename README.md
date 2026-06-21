# WARecon

Domain keşif ve güvenlik analiz platformu. Django + Tabler arayüzü ile Naabu, Subfinder, Waybackpy, HTTPX ve Nuclei araçlarını tek panelden çalıştırır.

## Gereksinimler

- Python 3.10+
- Go (tarama araçları için)
- `pip`, `venv`

## Kurulum

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Go tabanlı araçlar (naabu, subfinder, httpx, nuclei)
bash install_tools.sh
export PATH="$PATH:$HOME/go/bin"

# Veritabanı
python manage.py migrate

# (İsteğe bağlı) Admin kullanıcısı
python manage.py createsuperuser
```

## Çalıştırma

```bash
export PATH="$PATH:$HOME/go/bin"
python manage.py runserver
```

Tarayıcı: http://127.0.0.1:8000/

Admin panel: http://127.0.0.1:8000/admin/

## Proje Yapısı

```
warecon/          # Django ayarları
scans/            # Ana uygulama
  models.py       # Tarama geçmişi (Scan, ScanModuleResult)
  services/       # CLI araç entegrasyonu + pipeline
templates/        # Tabler arayüz şablonları
static/           # CSS, JS
outputs/          # Tarama çıktı dosyaları
```

## Pipeline Sırası

Modüller otomatik olarak şu sırada çalışır:

1. Subdomain (Subfinder)
2. Wayback URL
3. HTTPX
4. Port (Naabu)
5. Nuclei

## Araçlar

- [Naabu](https://github.com/projectdiscovery/naabu) — Port tarama
- [Subfinder](https://github.com/projectdiscovery/subfinder) — Subdomain keşfi
- [Waybackpy](https://pypi.org/project/waybackpy/) — Arşiv URL
- [HTTPX](https://github.com/projectdiscovery/httpx) — Canlı URL doğrulama
- [Nuclei](https://github.com/projectdiscovery/nuclei) — Zafiyet tarama

## Sorumluluk Reddi

Bu araç yalnızca eğitim ve yetkili güvenlik testleri içindir. Hedef sistemlerde izin almadan kullanmayın.

## İletişim

[Musa ATALAY](https://tr.linkedin.com/in/musatalayy)
