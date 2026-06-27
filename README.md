# WARecon

Domain keşif ve güvenlik analiz platformu. **Django 5** + **[Black Dashboard](https://github.com/creativetimofficial/black-dashboard-django)** arayüzü, **Redis/RQ** arka plan görevleri, REST API ve PDF rapor desteği.

## Özellikler

- Port, subdomain, DNS, Wayback, HTTPX, Katana crawl, Nuclei zafiyet taraması
- **OSINT subdomain istihbaratı** — canlı hedefler için AlienVault OTX skorlama (Top 5 Kritik Hedef)
- Otomatik pipeline sıralaması
- Arka planda tarama (sayfa donmaz)
- Canlı ilerleme (SSE)
- Kullanıcı girişi ve kişisel tarama geçmişi
- REST API (`/api/scans/`)
- HTML / PDF rapor export
- Django Admin paneli

## Kurulum

### Docker (önerilen)

```bash
cp .env.example .env
# .env içinde DJANGO_SECRET_KEY değiştirin
# OSINT için (ücretsiz): OTX_API_KEY=...  https://otx.alienvault.com/api

docker compose up --build -d

# İlk kullanıcı
docker compose exec web python manage.py createsuperuser
```

- Uygulama: http://127.0.0.1:8000/
- Veritabanı ve tarama çıktıları `warecon_data` volume içinde kalır
- `web` (Gunicorn) + `worker` (RQ) + `redis` birlikte çalışır
- ProjectDiscovery araçları Docker imajına GitHub release binary'leri ile eklenir (`docker/install-pd-tools.sh`)

Durdurmak: `docker compose down`  
Verileri de silmek: `docker compose down -v`

### Manuel kurulum

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

bash install_tools.sh
export PATH="$PATH:$HOME/go/bin"

# Redis (arka plan işleri)
sudo service redis-server start

python manage.py migrate
python manage.py createsuperuser
```

## Çalıştırma

3 terminal gerekir:

```bash
# 1 — Redis (bir kez)
sudo service redis-server start

# 2 — RQ worker
export PATH="$PATH:$HOME/go/bin"
python manage.py rqworker default

# 3 — Django
export PATH="$PATH:$HOME/go/bin"
python manage.py runserver
```

- Uygulama: http://127.0.0.1:8000/
- Admin: http://127.0.0.1:8000/admin/
- API: http://127.0.0.1:8000/api/scans/
- RQ durumu: http://127.0.0.1:8000/django-rq/

## API Kullanımı

Oturum açtıktan sonra (tarayıcıda login) veya Basic Auth ile:

```bash
# Tarama başlat
curl -u admin:password -X POST http://127.0.0.1:8000/api/scans/start/ \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","choices":["4"],"httpxStatusCode":true}'

# Tarama listesi
curl -u admin:password http://127.0.0.1:8000/api/scans/

# Tarama detayı
curl -u admin:password http://127.0.0.1:8000/api/scans/1/
```

## Pipeline Sırası

1. Subfinder → 2. dnsx → 3. Wayback → 4. HTTPX → 5. Katana → 6. Naabu → 7. Nuclei

## Proje Yapısı

```
warecon/           Django ayarları
scans/
  models.py        Scan, ScanModuleResult
  services/        CLI araçları, pipeline, raporlar
  tasks.py         RQ arka plan görevleri
  api.py           REST API
templates/         Tabler arayüz
static/
outputs/           Tarama dosyaları
```

## Sorumluluk Reddi

Yalnızca yetkili güvenlik testleri için kullanın.

## İletişim

[Musa ATALAY](https://tr.linkedin.com/in/musatalayy)
