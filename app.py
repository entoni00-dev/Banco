"""Banco — trova compagni di studio nel tuo ateneo (MVP, lancio Federico II).

Funziona in locale con SQLite e online con Postgres (es. Neon) tramite la
variabile d'ambiente DATABASE_URL.
"""
import json
import os
import secrets
import urllib.request
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, abort, flash, redirect, render_template, request,
                   session, url_for)
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from courses import ALL_LABELS, grouped_labels

# ---------------------------------------------------------------- config
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

IS_PROD = bool(os.environ.get("RENDER") or os.environ.get("DATABASE_URL"))
DEMO_MODE = os.environ.get("DEMO_MODE", "1") == "1"
# "*" = qualsiasi email; vuoto = solo il dominio dell'ateneo attivo (studenti.unina.it)
ALLOWED_EMAIL_DOMAIN = os.environ.get("ALLOWED_EMAIL_DOMAIN", "").strip().lower()
# Email (Brevo, via API HTTPS: Render gratuito blocca l'SMTP). Senza chiave i link finiscono nei log.
BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "").strip()
MAIL_FROM = os.environ.get("MAIL_FROM", "").strip()
MAIL_FROM_NAME = os.environ.get("MAIL_FROM_NAME", "Banco")


def _database_url():
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        return "sqlite:///banco.db"
    # Neon/Heroku danno "postgres://" o "postgresql://": usiamo il driver psycopg 3
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://"):]
    return url


app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-change-me"),
    SQLALCHEMY_DATABASE_URI=_database_url(),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    # Neon spegne il DB dopo 5 minuti di inattività: verifica la connessione prima di usarla
    SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True, "pool_recycle": 280},
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PROD,
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),   # resti dentro 30 giorni
)
db = SQLAlchemy(app)

DAYS = ["Lun", "Mar", "Mer", "Gio", "Ven", "Sab", "Dom"]
SLOTS = ["Mattina", "Pomeriggio", "Sera"]
MODES = ["Presenza", "Online"]
STATUS_LABELS = {"pending": "In attesa", "accepted": "Accettata", "rejected": "Rifiutata"}
DEMO_DOMAIN = "demo.banco"


# ---------------------------------------------------------------- modelli
class University(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email_domain = db.Column(db.String(120), unique=True, nullable=False)
    active = db.Column(db.Boolean, default=False)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(160), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(60), nullable=False)
    degree = db.Column(db.String(120), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    bio = db.Column(db.String(150), default="")
    contact = db.Column(db.String(160), default="")
    university_id = db.Column(db.Integer, db.ForeignKey("university.id"), nullable=False)
    university = db.relationship("University")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def is_demo(self):
        return self.email.endswith("@" + DEMO_DOMAIN)


class StudyRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(120), nullable=False)
    days = db.Column(db.String(100), nullable=False)
    time_slot = db.Column(db.String(30), nullable=False)
    mode = db.Column(db.String(20), nullable=False)
    place = db.Column(db.String(120), default="")
    note = db.Column(db.String(220), default="")
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User")


class ContactRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    study_request_id = db.Column(db.Integer, db.ForeignKey("study_request.id"), nullable=False)
    status = db.Column(db.String(20), default="pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sender = db.relationship("User", foreign_keys=[sender_id])
    receiver = db.relationship("User", foreign_keys=[receiver_id])
    study_request = db.relationship("StudyRequest")


class Attempt(db.Model):
    """Tentativi registrati per i limiti anti-abuso (login sbagliati, recuperi password, ecc.).
    Sta nel database così il limite vale anche con più processi e dopo un riavvio."""
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(200), index=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


# ---------------------------------------------------------------- limiti anti-abuso
# (azione, chi) -> (massimo, finestra in minuti).
# I limiti per IP sono larghi apposta: all'università centinaia di studenti escono
# dallo stesso indirizzo (wifi dell'ateneo), e non vogliamo bloccarli tutti insieme.
LIMITS = {
    ("login", "email"): (5, 15),     # 5 password sbagliate su un account → pausa di 15 minuti
    ("login", "ip"): (50, 15),
    ("reset", "email"): (3, 60),     # max 3 email di recupero l'ora per account (protegge la quota Brevo)
    ("reset", "ip"): (20, 60),
    ("register", "ip"): (60, 60),
    ("demo", "ip"): (30, 60),
}


def client_ip():
    return request.remote_addr or "?"


def _key(action, who, value):
    return ("%s:%s:%s" % (action, who, value))[:200]


def too_many(action, email=None):
    """True se l'azione ha superato il limite per questo IP o per questa email."""
    checks = [("ip", client_ip())] + ([("email", email)] if email else [])
    for who, value in checks:
        limit = LIMITS.get((action, who))
        if not limit:
            continue
        since = datetime.utcnow() - timedelta(minutes=limit[1])
        n = Attempt.query.filter(Attempt.key == _key(action, who, value),
                                 Attempt.created_at >= since).count()
        if n >= limit[0]:
            app.logger.warning("Limite superato: %s %s=%s", action, who, value)
            return True
    return False


def record(action, email=None):
    db.session.add(Attempt(key=_key(action, "ip", client_ip())))
    if email:
        db.session.add(Attempt(key=_key(action, "email", email)))
    # pulizia: i tentativi più vecchi di un giorno non servono più
    if secrets.randbelow(50) == 0:
        Attempt.query.filter(Attempt.created_at < datetime.utcnow() - timedelta(days=1)).delete()
    db.session.commit()


def safe_next(target):
    """Dopo il login si torna solo a pagine di Banco, mai a siti esterni."""
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return url_for("feed")


# ---------------------------------------------------------------- helper
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    user = db.session.get(User, uid)
    if user is None:          # utente cancellato / DB ricreato
        session.clear()
    return user


def log_in(user):
    session.clear()
    session.permanent = True
    session["user_id"] = user.id


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Accedi per continuare.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("_csrf", "")
        if not sent or not secrets.compare_digest(sent, session.get("_csrf", "")):
            flash("Sessione scaduta, riprova.", "error")
            return redirect(request.referrer or url_for("index"))


@app.context_processor
def inject_globals():
    me = current_user()
    pending = 0
    if me:
        pending = ContactRequest.query.filter_by(receiver_id=me.id, status="pending").count()
    return {"me": me, "csrf_token": csrf_token, "pending_count": pending,
            "STATUS_LABELS": STATUS_LABELS, "DEMO_MODE": DEMO_MODE,
            "DAYS": DAYS, "SLOTS": SLOTS, "MODES": MODES,
            "COURSE_GROUPS": COURSE_GROUPS, "ALL_COURSES": ALL_LABELS}


COURSE_GROUPS = grouped_labels()
OTHER = "__altro__"


def parse_degree(current=None):
    """Corso scelto dal menu; 'Altro' usa il testo libero. Accetta il valore attuale (profili vecchi)."""
    choice = request.form.get("degree", "").strip()
    if choice == OTHER:
        other = clean("degree_other", 120)
        return other or None
    if choice in ALL_LABELS or (current and choice == current):
        return choice
    return None


def email_allowed(email, uni):
    if ALLOWED_EMAIL_DOMAIN == "*":
        return "@" in email
    domain = ALLOWED_EMAIL_DOMAIN or (uni.email_domain if uni else "studenti.unina.it")
    return email.endswith("@" + domain)


def send_email(to, subject, html):
    """Invia con Brevo. Se non configurato, scrive nei log (visibili su Render → Logs)."""
    if not (BREVO_API_KEY and MAIL_FROM):
        app.logger.warning("EMAIL NON INVIATA (Brevo non configurato) a %s | %s | %s", to, subject, html)
        return False
    body = json.dumps({"sender": {"email": MAIL_FROM, "name": MAIL_FROM_NAME},
                       "to": [{"email": to}], "subject": subject, "htmlContent": html}).encode()
    req = urllib.request.Request("https://api.brevo.com/v3/smtp/email", data=body, method="POST",
                                 headers={"api-key": BREVO_API_KEY, "content-type": "application/json",
                                          "accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return 200 <= r.status < 300
    except Exception as exc:          # l'app non deve rompersi se l'email fallisce
        app.logger.error("Invio email fallito a %s: %s", to, exc)
        return False


def email_layout(title, text, button_label=None, button_url=None):
    btn = ""
    if button_url:
        btn = ('<p><a href="%s" style="background:#e8b84b;color:#1c241e;padding:12px 18px;'
               'text-decoration:none;font-weight:600;display:inline-block">%s</a></p>'
               '<p style="font-size:12px;color:#6d746f">Se il pulsante non funziona copia questo link: %s</p>'
               % (button_url, button_label, button_url))
    return ('<div style="font-family:Arial,sans-serif;max-width:520px;color:#17231c">'
            '<h2 style="color:#1f3b2c">%s</h2><p>%s</p>%s'
            '<p style="font-size:12px;color:#6d746f">Banco · studia in compagnia</p></div>' % (title, text, btn))


def notify(user, subject, text, button_label, endpoint):
    if user.is_demo:
        return
    send_email(user.email, subject, email_layout(subject, text, button_label,
                                                 url_for(endpoint, _external=True)))


def reset_serializer():
    return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="password-reset")


def active_university():
    return University.query.filter_by(active=True).first()


def clean(field, limit):
    return request.form.get(field, "").strip()[:limit]


def parse_year(raw):
    try:
        year = int(raw)
    except (TypeError, ValueError):
        return None
    return year if 1 <= year <= 6 else None


# ---------------------------------------------------------------- pagine pubbliche
@app.route("/")
def index():
    if current_user():
        return redirect(url_for("feed"))
    return render_template("index.html")


@app.route("/health")
def health():
    return "ok"


@app.route("/register", methods=["GET", "POST"])
def register():
    uni = active_university()
    domain = ALLOWED_EMAIL_DOMAIN if ALLOWED_EMAIL_DOMAIN not in ("", "*") else (
        uni.email_domain if uni else "studenti.unina.it")
    if request.method == "POST":
        email = clean("email", 160).lower()
        password = request.form.get("password", "")
        name, degree = clean("name", 60), parse_degree()
        year = parse_year(request.form.get("year"))
        error = None
        if too_many("register"):
            flash("Troppe registrazioni da questa rete. Riprova tra un po'.", "error")
            return redirect(url_for("register"))
        if not email_allowed(email, uni):
            error = "Per il lancio accettiamo solo email @%s." % domain
        elif User.query.filter_by(email=email).first():
            flash("Questa email è già registrata: accedi.", "error")
            return redirect(url_for("login"))
        elif not name:
            error = "Il nome è obbligatorio."
        elif not degree:
            error = "Scegli il tuo corso dall'elenco (o \"Altro\" e scrivilo)."
        elif year is None:
            error = "Anno di corso non valido."
        elif len(password) < 6:
            error = "La password deve avere almeno 6 caratteri."
        if error:
            flash(error, "error")
            return render_template("register.html", domain=domain, form=request.form,
                                   any_email=ALLOWED_EMAIL_DOMAIN == "*")
        user = User(email=email, password_hash=generate_password_hash(password),
                    name=name, degree=degree, year=year,
                    bio=clean("bio", 150), contact=clean("contact", 160), university=uni)
        db.session.add(user)
        db.session.commit()
        record("register")
        log_in(user)
        flash("Benvenuto su Banco, %s." % user.name, "success")
        return redirect(url_for("feed"))
    return render_template("register.html", domain=domain, form={},
                           any_email=ALLOWED_EMAIL_DOMAIN == "*")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = clean("email", 160).lower()
        if too_many("login", email):
            flash("Troppi tentativi sbagliati. Aspetta 15 minuti oppure usa \"Password dimenticata\".",
                  "error")
            return redirect(url_for("login"))
        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, request.form.get("password", "")):
            record("login", email)
            flash("Email o password non corretti.", "error")
            return redirect(url_for("login"))
        log_in(user)
        return redirect(safe_next(request.args.get("next")))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------------------------------------------------------------- password dimenticata
RESET_MAX_AGE = 60 * 60  # il link vale 1 ora


@app.route("/password/dimenticata", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = clean("email", 160).lower()
        # oltre il limite non mandiamo nulla, ma la risposta resta identica
        # (così non si capisce né chi è iscritto né quando è scattato il blocco)
        limited = too_many("reset", email)
        if not limited:
            record("reset", email)
        user = None if limited else User.query.filter_by(email=email).first()
        if user and not user.is_demo:
            # l'impronta della password rende il link usa-e-getta: cambiata la password, non vale più
            token = reset_serializer().dumps({"u": user.id, "p": user.password_hash[-12:]})
            link = url_for("reset_password", token=token, _external=True)
            send_email(user.email, "Reimposta la password di Banco", email_layout(
                "Reimposta la password",
                "Ciao %s, hai chiesto di cambiare la password. Il link vale un'ora. "
                "Se non sei stato tu, ignora questa email." % user.name,
                "Scegli una nuova password", link))
        # stessa risposta sempre, così non si scopre quali email sono registrate
        flash("Se l'email è registrata, ti abbiamo mandato un link per reimpostare la password "
              "(controlla anche lo spam).", "success")
        return redirect(url_for("login"))
    return render_template("forgot.html")


@app.route("/password/nuova/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        data = reset_serializer().loads(token, max_age=RESET_MAX_AGE)
    except SignatureExpired:
        flash("Il link è scaduto: richiedine uno nuovo.", "error")
        return redirect(url_for("forgot_password"))
    except BadSignature:
        flash("Link non valido.", "error")
        return redirect(url_for("forgot_password"))
    user = db.session.get(User, data.get("u"))
    if not user or user.password_hash[-12:] != data.get("p"):
        flash("Questo link è già stato usato: richiedine uno nuovo.", "error")
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        pw = request.form.get("password", "")
        if len(pw) < 6:
            flash("La password deve avere almeno 6 caratteri.", "error")
            return redirect(request.path)
        if pw != request.form.get("password2", ""):
            flash("Le due password non coincidono.", "error")
            return redirect(request.path)
        user.password_hash = generate_password_hash(pw)
        db.session.commit()
        log_in(user)
        flash("Password aggiornata: sei dentro.", "success")
        return redirect(url_for("feed"))
    return render_template("reset.html", name=user.name)


# ---------------------------------------------------------------- demo
DEMO_PEOPLE = [
    ("Giulia", "Ingegneria Informatica · Triennale", 1, "Analisi Matematica I", "Mar, Gio", "Pomeriggio", "Presenza",
     "Biblioteca San Giovanni", "Cerco qualcuno per fare esercizi sugli integrali, ritmo tranquillo."),
    ("Marco", "Economia Aziendale · Triennale", 2, "Statistica", "Lun, Mer", "Mattina", "Online",
     "", "Preparo lo scritto di giugno, confronto sugli esercizi d'esame."),
    ("Sara", "Giurisprudenza · Ciclo unico", 3, "Diritto Privato", "Mar, Ven", "Mattina", "Presenza",
     "Via Porta di Massa", "Ripasso a voce: ci facciamo domande a vicenda."),
    ("Luca", "Ingegneria Gestionale · Triennale", 1, "Programmazione I", "Gio", "Sera", "Online",
     "", "Esercizi in C, posso aiutare con i puntatori."),
    ("Chiara", "Medicina e Chirurgia · Ciclo unico", 2, "Biochimica", "Lun, Mar, Mer", "Pomeriggio", "Presenza",
     "Policlinico", "Schemi e mappe, cerco 1-2 persone costanti."),
    ("Davide", "Fisica · Triennale", 1, "Fisica I", "Sab", "Mattina", "Presenza",
     "Monte Sant'Angelo", "Problemi di cinematica e dinamica dal Mazzoldi."),
]


def seed_demo():
    """Crea studenti e richieste di esempio (solo se mancano). Sono marcati come demo."""
    uni = active_university()
    if User.query.filter(User.email.like("%@" + DEMO_DOMAIN)).filter(
            ~User.email.like("ospite%")).first():
        return
    for i, (name, degree, year, subject, days, slot, mode, place, note) in enumerate(DEMO_PEOPLE):
        u = User(email="studente%d@%s" % (i + 1, DEMO_DOMAIN),
                 password_hash=generate_password_hash(secrets.token_hex(16)),
                 name=name, degree=degree, year=year,
                 bio="Profilo dimostrativo.", contact="@%s_demo" % name.lower(), university=uni)
        db.session.add(u)
        db.session.add(StudyRequest(subject=subject, days=days, time_slot=slot, mode=mode,
                                    place=place, note=note, user=u))
    db.session.commit()


@app.post("/demo")
def demo_login():
    """Crea un ospite nuovo a ogni clic, così chi prova la demo non vede le azioni degli altri."""
    if not DEMO_MODE:
        abort(404)
    if too_many("demo"):
        flash("Troppe demo avviate da questa rete. Riprova tra un po'.", "error")
        return redirect(url_for("index"))
    record("demo")
    seed_demo()
    uni = active_university()
    guest = User(email="ospite-%s@%s" % (secrets.token_hex(4), DEMO_DOMAIN),
                 password_hash=generate_password_hash(secrets.token_hex(16)),
                 name="Ospite", degree="Ingegneria Informatica · Triennale", year=1,
                 bio="Sto provando Banco.", contact="@ospite_demo", university=uni)
    db.session.add(guest)
    db.session.flush()
    my_req = StudyRequest(subject="Analisi Matematica I", days="Mar, Gio", time_slot="Pomeriggio",
                          mode="Presenza", place="Biblioteca San Giovanni",
                          note="Esempio: questa è una tua richiesta.", user=guest)
    db.session.add(my_req)
    db.session.flush()
    # una richiesta di contatto in arrivo, così si può provare "Accetta"
    giulia = User.query.filter_by(email="studente1@" + DEMO_DOMAIN).first()
    if giulia:
        db.session.add(ContactRequest(sender_id=giulia.id, receiver_id=guest.id,
                                      study_request_id=my_req.id))
    db.session.commit()
    log_in(guest)
    flash("Sei dentro come ospite. I profili che vedi sono esempi dimostrativi.", "success")
    return redirect(url_for("feed"))


# ---------------------------------------------------------------- app
@app.route("/feed")
@login_required
def feed():
    me = current_user()
    q = StudyRequest.query.filter(StudyRequest.active.is_(True), StudyRequest.user_id != me.id)
    subject = request.args.get("subject", "").strip()
    mode = request.args.get("mode", "").strip()
    slot = request.args.get("slot", "").strip()
    if subject:
        q = q.filter(StudyRequest.subject.ilike("%" + subject + "%"))
    if mode in MODES:
        q = q.filter_by(mode=mode)
    if slot in SLOTS:
        q = q.filter_by(time_slot=slot)
    # gli ospiti demo vedono solo i profili demo; gli utenti veri solo quelli veri
    q = q.join(User, StudyRequest.user_id == User.id)
    if me.is_demo:
        q = q.filter(User.email.like("studente%@" + DEMO_DOMAIN))   # niente richieste di altri ospiti
    else:
        q = q.filter(~User.email.like("%@" + DEMO_DOMAIN))
    items = q.order_by(StudyRequest.created_at.desc()).all()
    sent = {c.study_request_id: c.status for c in ContactRequest.query.filter_by(sender_id=me.id)}
    return render_template("feed.html", items=items, sent=sent,
                           f={"subject": subject, "mode": mode, "slot": slot})


@app.route("/request/new", methods=["GET", "POST"])
@login_required
def new_request():
    me = current_user()
    if request.method == "POST":
        days = [d for d in request.form.getlist("days") if d in DAYS]
        subject = clean("subject", 120)
        slot, mode = request.form.get("time_slot"), request.form.get("mode")
        error = None
        if not subject:
            error = "Indica la materia."
        elif not days:
            error = "Seleziona almeno un giorno."
        elif slot not in SLOTS or mode not in MODES:
            error = "Fascia oraria o modalità non valida."
        if error:
            flash(error, "error")
            return render_template("new_request.html", form=request.form, sel_days=days)
        db.session.add(StudyRequest(subject=subject, days=", ".join(days), time_slot=slot, mode=mode,
                                    place=clean("place", 120), note=clean("note", 220), user=me))
        db.session.commit()
        flash("Richiesta pubblicata.", "success")
        return redirect(url_for("my_requests"))
    return render_template("new_request.html", form={}, sel_days=[])


@app.route("/my-requests")
@login_required
def my_requests():
    me = current_user()
    items = StudyRequest.query.filter_by(user_id=me.id).order_by(StudyRequest.created_at.desc()).all()
    return render_template("my_requests.html", items=items)


@app.post("/request/<int:req_id>/<action>")
@login_required
def request_action(req_id, action):
    me = current_user()
    item = db.session.get(StudyRequest, req_id) or abort(404)
    if item.user_id != me.id:
        abort(403)
    if action == "close":
        item.active = False
        flash("Richiesta chiusa: non compare più in bacheca.", "success")
    elif action == "reopen":
        item.active = True
        flash("Richiesta di nuovo visibile.", "success")
    elif action == "delete":
        ContactRequest.query.filter_by(study_request_id=item.id).delete()
        db.session.delete(item)
        flash("Richiesta eliminata.", "success")
    else:
        abort(400)
    db.session.commit()
    return redirect(url_for("my_requests"))


@app.post("/request/<int:req_id>/contact")
@login_required
def send_contact(req_id):
    me = current_user()
    study = db.session.get(StudyRequest, req_id) or abort(404)
    if study.user_id == me.id or not study.active:
        abort(400)
    existing = ContactRequest.query.filter_by(sender_id=me.id, study_request_id=req_id).first()
    if existing:
        flash("Hai già inviato una richiesta per questo annuncio.", "error")
        return redirect(url_for("feed"))
    cr = ContactRequest(sender_id=me.id, receiver_id=study.user_id, study_request_id=req_id)
    # in demo i profili di esempio accettano subito, così si vede lo sblocco del contatto
    if me.is_demo and study.user.is_demo:
        cr.status = "accepted"
        flash("%s ha accettato (demo): trovi il contatto in Contatti." % study.user.name, "success")
    else:
        flash("Richiesta di contatto inviata a %s." % study.user.name, "success")
    db.session.add(cr)
    db.session.commit()
    if cr.status == "pending":
        notify(study.user, "%s vuole studiare %s con te" % (me.name, study.subject),
               "%s (%s, %s° anno) ha risposto alla tua richiesta su Banco. Accetta per scambiarvi i contatti."
               % (me.name, me.degree, me.year), "Vedi la richiesta", "contacts")
    return redirect(url_for("feed"))


@app.route("/contacts")
@login_required
def contacts():
    me = current_user()
    incoming = ContactRequest.query.filter_by(receiver_id=me.id).order_by(ContactRequest.created_at.desc()).all()
    outgoing = ContactRequest.query.filter_by(sender_id=me.id).order_by(ContactRequest.created_at.desc()).all()
    return render_template("contacts.html", incoming=incoming, outgoing=outgoing)


@app.post("/contact/<int:cid>/<action>")
@login_required
def contact_action(cid, action):
    me = current_user()
    cr = db.session.get(ContactRequest, cid) or abort(404)
    if cr.receiver_id != me.id:
        abort(403)
    if action not in ("accepted", "rejected"):
        abort(400)
    cr.status = action
    db.session.commit()
    if action == "accepted":
        notify(cr.sender, "%s ha accettato: potete studiare insieme" % me.name,
               "%s ha accettato la tua richiesta per %s. Trovi il suo contatto su Banco."
               % (me.name, cr.study_request.subject), "Apri i contatti", "contacts")
    flash("Contatto sbloccato." if action == "accepted" else "Richiesta rifiutata.", "success")
    return redirect(url_for("contacts"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    me = current_user()
    if request.method == "POST":
        name, degree = clean("name", 60), parse_degree(current=me.degree)
        year = parse_year(request.form.get("year"))
        if not name or not degree or year is None:
            flash("Controlla nome, corso e anno.", "error")
            return redirect(url_for("profile"))
        me.name, me.degree, me.year = name, degree, year
        me.bio, me.contact = clean("bio", 150), clean("contact", 160)
        new_pw = request.form.get("new_password", "")
        if new_pw:
            if len(new_pw) < 6:
                flash("La nuova password deve avere almeno 6 caratteri.", "error")
                return redirect(url_for("profile"))
            me.password_hash = generate_password_hash(new_pw)
        db.session.commit()
        flash("Profilo aggiornato.", "success")
        return redirect(url_for("profile"))
    return render_template("profile.html")


# ---------------------------------------------------------------- errori
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(400)
def error_page(e):
    return render_template("error.html", code=e.code), e.code


# ---------------------------------------------------------------- avvio
with app.app_context():
    db.create_all()
    if not University.query.filter_by(email_domain="studenti.unina.it").first():
        db.session.add(University(name="Università degli Studi di Napoli Federico II",
                                  email_domain="studenti.unina.it", active=True))
        db.session.commit()
    if DEMO_MODE:
        seed_demo()

if __name__ == "__main__":
    app.run(debug=True)
