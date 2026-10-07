"""Banco — trova compagni di studio nel tuo ateneo (MVP, lancio Federico II).

Funziona in locale con SQLite e online con Postgres (es. Neon) tramite la
variabile d'ambiente DATABASE_URL.
"""
import os
import secrets
from datetime import datetime
from functools import wraps

from flask import (Flask, abort, flash, redirect, render_template, request,
                   session, url_for)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------- config
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

IS_PROD = bool(os.environ.get("RENDER") or os.environ.get("DATABASE_URL"))
DEMO_MODE = os.environ.get("DEMO_MODE", "1") == "1"


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


# ---------------------------------------------------------------- helper
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    user = db.session.get(User, uid)
    if user is None:          # utente cancellato / DB ricreato
        session.clear()
    return user


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
            "DAYS": DAYS, "SLOTS": SLOTS, "MODES": MODES}


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
    domain = uni.email_domain if uni else "studenti.unina.it"
    if request.method == "POST":
        email = clean("email", 160).lower()
        password = request.form.get("password", "")
        name, degree = clean("name", 60), clean("degree", 120)
        year = parse_year(request.form.get("year"))
        error = None
        if not uni or not email.endswith("@" + domain):
            error = "Per il lancio accettiamo solo email @%s." % domain
        elif User.query.filter_by(email=email).first():
            flash("Questa email è già registrata: accedi.", "error")
            return redirect(url_for("login"))
        elif not name or not degree:
            error = "Nome e corso di laurea sono obbligatori."
        elif year is None:
            error = "Anno di corso non valido."
        elif len(password) < 6:
            error = "La password deve avere almeno 6 caratteri."
        if error:
            flash(error, "error")
            return render_template("register.html", domain=domain, form=request.form)
        user = User(email=email, password_hash=generate_password_hash(password),
                    name=name, degree=degree, year=year,
                    bio=clean("bio", 150), contact=clean("contact", 160), university=uni)
        db.session.add(user)
        db.session.commit()
        session.clear()
        session["user_id"] = user.id
        flash("Benvenuto su Banco, %s." % user.name, "success")
        return redirect(url_for("feed"))
    return render_template("register.html", domain=domain, form={})


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(email=clean("email", 160).lower()).first()
        if not user or not check_password_hash(user.password_hash, request.form.get("password", "")):
            flash("Email o password non corretti.", "error")
            return redirect(url_for("login"))
        session.clear()
        session["user_id"] = user.id
        return redirect(url_for("feed"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------------------------------------------------------------- demo
DEMO_PEOPLE = [
    ("Giulia", "Ingegneria Informatica", 1, "Analisi Matematica I", "Mar, Gio", "Pomeriggio", "Presenza",
     "Biblioteca San Giovanni", "Cerco qualcuno per fare esercizi sugli integrali, ritmo tranquillo."),
    ("Marco", "Economia Aziendale", 2, "Statistica", "Lun, Mer", "Mattina", "Online",
     "", "Preparo lo scritto di giugno, confronto sugli esercizi d'esame."),
    ("Sara", "Giurisprudenza", 3, "Diritto Privato", "Mar, Ven", "Mattina", "Presenza",
     "Via Porta di Massa", "Ripasso a voce: ci facciamo domande a vicenda."),
    ("Luca", "Ingegneria Gestionale", 1, "Programmazione I", "Gio", "Sera", "Online",
     "", "Esercizi in C, posso aiutare con i puntatori."),
    ("Chiara", "Medicina e Chirurgia", 2, "Biochimica", "Lun, Mar, Mer", "Pomeriggio", "Presenza",
     "Policlinico", "Schemi e mappe, cerco 1-2 persone costanti."),
    ("Davide", "Fisica", 1, "Fisica I", "Sab", "Mattina", "Presenza",
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
    seed_demo()
    uni = active_university()
    guest = User(email="ospite-%s@%s" % (secrets.token_hex(4), DEMO_DOMAIN),
                 password_hash=generate_password_hash(secrets.token_hex(16)),
                 name="Ospite", degree="Ingegneria Informatica", year=1,
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
    session.clear()
    session["user_id"] = guest.id
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
    flash("Contatto sbloccato." if action == "accepted" else "Richiesta rifiutata.", "success")
    return redirect(url_for("contacts"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    me = current_user()
    if request.method == "POST":
        name, degree = clean("name", 60), clean("degree", 120)
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
