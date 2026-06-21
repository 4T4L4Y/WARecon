## Cursor Cloud specific instructions

### Docker (önerilen)
```bash
cp .env.example .env
docker compose up --build -d
docker compose exec web python manage.py createsuperuser
```
Servisler: `web` (Gunicorn :8000), `worker` (RQ), `redis`. Veri: volume `warecon_data` (`/data` → db.sqlite3 + outputs).

PD araçları (`naabu`, `subfinder`, `dnsx`, `httpx`, `katana`, `nuclei`) Dockerfile içinde `go install` ile değil, GitHub release binary'leri ile kurulur (`docker/install-pd-tools.sh`). Bu, Go sürüm uyumsuzluklarını ve CGO derleme hatalarını önler. Sürümleri güncellemek için bu script'teki pin'leri değiştirin.

### Manuel geliştirme
- Django: `python manage.py runserver 0.0.0.0:8000`
- RQ worker: `export PATH="$HOME/go/bin:/usr/bin:$PATH" && python manage.py rqworker default`
- Redis gerekli (`REDIS_HOST=localhost`)
- `python manage.py migrate` yeni migration sonrası

### Test / lint
- `python manage.py test scans`
