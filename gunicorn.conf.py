# Gunicorn legge questo file da solo: su Render lo Start Command resta "gunicorn app:app".
# Senza questo file gunicorn serve UNA richiesta alla volta; così ne gestisce fino a 8 insieme.
# 2 processi x 4 thread stanno comodi nei 512 MB del piano gratuito di Render.
import os

workers = int(os.environ.get("WEB_CONCURRENCY", 2))
threads = int(os.environ.get("GUNICORN_THREADS", 4))
worker_class = "gthread"
timeout = 60            # Neon può metterci qualche secondo a svegliarsi dopo una pausa

# L'app (creazione tabelle, dati demo) si prepara una volta sola prima di sdoppiarsi,
# così i processi non provano a creare le stesse tabelle nello stesso momento.
preload_app = True


def post_fork(server, worker):
    # ogni processo apre le sue connessioni al database, senza riusare quelle del padre
    from app import app, db
    with app.app_context():
        db.engine.dispose(close=False)
