from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = "hospital_secret"

# Database setup
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "hospital.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


# -------------------
# Database Models
# -------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # admin, doctor, patient


class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    disease = db.Column(db.String(200), nullable=False)


# -------------------
# Routes
# -------------------

@app.route("/")
def index():
    return render_template("index.html")


# ✅ Signup Route
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        role = request.form["role"]

        hashed_password = generate_password_hash(password, method="scrypt")
        new_user = User(username=username, email=email, password=hashed_password, role=role)

        db.session.add(new_user)
        db.session.commit()
        flash("Account created successfully! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")


# ✅ Login Route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["role"] = user.role
            flash("Login successful!", "success")

            if user.role == "admin":
                return redirect(url_for("admin_dashboard"))
            elif user.role == "doctor":
                return redirect(url_for("doctor_dashboard"))
            else:
                return redirect(url_for("patient_dashboard"))
        else:
            flash("Invalid email or password", "danger")

    return render_template("login.html")


# ✅ Logout
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully!", "info")
    return redirect(url_for("index"))


# -------------------
# Dashboards
# -------------------

@app.route("/admin_dashboard")
def admin_dashboard():
    if "role" in session and session["role"] == "admin":
        patients = Patient.query.all()
        return render_template("admin_dashboard.html", patients=patients)
    else:
        flash("Unauthorized Access", "danger")
        return redirect(url_for("login"))


@app.route("/doctor_dashboard")
def doctor_dashboard():
    if "role" in session and session["role"] == "doctor":
        patients = Patient.query.all()
        return render_template("doctor_dashboard.html", patients=patients)
    else:
        flash("Unauthorized Access", "danger")
        return redirect(url_for("login"))


@app.route("/patient_dashboard")
def patient_dashboard():
    if "role" in session and session["role"] == "patient":
        return render_template("patient_dashboard.html")
    else:
        flash("Unauthorized Access", "danger")
        return redirect(url_for("login"))


# -------------------
# Patient Management
# -------------------

@app.route("/add_patient", methods=["POST"])
def add_patient():
    if "role" in session and session["role"] in ["admin", "doctor"]:
        name = request.form["name"]
        age = request.form["age"]
        disease = request.form["disease"]

        patient = Patient(name=name, age=age, disease=disease)
        db.session.add(patient)
        db.session.commit()
        flash("Patient added successfully!", "success")

    return redirect(url_for("admin_dashboard"))


@app.route("/delete_patient/<int:id>")
def delete_patient(id):
    if "role" in session and session["role"] == "admin":
        patient = Patient.query.get(id)
        if patient:
            db.session.delete(patient)
            db.session.commit()
            flash("Patient deleted successfully!", "info")
    return redirect(url_for("admin_dashboard"))


# -------------------
# Run App
# -------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
