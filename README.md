# Banco

Web app per trovare compagni di studio alla Federico II.

## Cosa fa
- Registrazione solo con email `@studenti.unina.it`, login, modifica profilo e password
- Pubblicazione richieste di studio (materia, giorni, fascia, modalità, luogo, nota)
- Bacheca filtrabile per materia, modalità e orario
- Richiesta di contatto → l'altro accetta o rifiuta → il contatto si sblocca solo dopo l'accettazione
- Chiudi / riapri / elimina le tue richieste
- Menu in basso su telefono, contatore delle richieste in attesa
- **Demo per chi non ha email unina**: pulsante "Prova la demo" in homepage. Ogni clic crea un ospite nuovo
  con profili di esempio separati da quelli veri (gli utenti veri non li vedono mai).
  Si spegne impostando `DEMO_MODE=0`.

## Avvio sul tuo Mac

```bash
cd ~/Desktop/banco
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Apri http://127.0.0.1:5000 (in locale usa SQLite, file `instance/banco.db`).

---

## Pubblicarlo online gratis: GitHub + Neon + Render

| Servizio | A cosa serve | Costo |
|---|---|---|
| **GitHub** | contiene il codice | gratis |
| **Neon** (neon.com) | database Postgres, i dati restano | gratis per sempre, niente carta |
| **Render** (render.com) | fa girare l'app e ti dà il link `https://...onrender.com` | gratis (piano Free) |

> Perché non il database gratuito di Render? Viene **cancellato dopo 30 giorni**. Neon no.

### 1. GitHub — carica il codice
1. Crea un account su github.com → **New repository** → nome `banco` → *Private* va bene → **Create**.
2. Clicca **uploading an existing file** e trascina **il contenuto** della cartella estratta dallo zip
   (`app.py`, `requirements.txt`, `README.md`, cartelle `templates` e `static`).
   **Non** caricare `.venv` né `instance`.
3. **Commit changes**.

### 2. Neon — crea il database
1. Registrati su neon.com (anche con l'account GitHub) → **Create project** → nome `banco`, regione **Europe (Frankfurt)**.
2. Nella dashboard clicca **Connect** e copia la *connection string*. È tipo:
   `postgresql://utente:password@ep-xxxx.eu-central-1.aws.neon.tech/neondb?sslmode=require`
3. Tienila da parte: è una password, non condividerla.

### 3. Render — metti online l'app
1. Registrati su render.com con GitHub → **New** → **Web Service** → scegli il repository `banco`.
2. Impostazioni:
   - **Language**: Python 3
   - **Region**: Frankfurt
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
   - **Instance Type**: **Free**
3. **Environment Variables** (Add Environment Variable):
   | Key | Value |
   |---|---|
   | `DATABASE_URL` | la stringa copiata da Neon |
   | `SECRET_KEY` | clicca **Generate** (o una frase lunga e casuale) |
   | `PYTHON_VERSION` | `3.12.8` |
   | `DEMO_MODE` | `1` (demo attiva) oppure `0` |
4. **Deploy Web Service**. Dopo 2-3 minuti in alto trovi il link `https://banco-xxxx.onrender.com`: è quello da mostrare.

### Aggiornare l'app
Modifichi i file su GitHub (o ricarichi quelli nuovi) → Render ripubblica da solo.

### Limiti del gratuito (da sapere prima di mostrarla)
- Render Free **si addormenta dopo 15 minuti senza visite**: la prima apertura dopo la pausa ci mette ~1 minuto.
  Prima di una presentazione, apri il link 2 minuti prima.
- Neon Free: circa 1 GB di dati per progetto, più che sufficienti per migliaia di utenti di prova.

## Cosa manca prima di un lancio vero
- **Verifica email**: oggi chiunque può registrarsi con un indirizzo `@studenti.unina.it` che non è suo.
  Serve un invio email di conferma (es. Brevo o Resend, entrambi con piano gratuito).
- Recupero password, segnalazione/blocco utenti, privacy policy (GDPR: trattate dati di studenti).
