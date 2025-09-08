from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hms.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Change this for production
db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin', 'doctor', 'patient'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer)
    gender = db.Column(db.String(10))
    address = db.Column(db.String(200))
    phone = db.Column(db.String(20))
    medical_history = db.Column(db.Text)
    user = db.relationship('User', backref='patient', uselist=False)

class Doctor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    specialization = db.Column(db.String(100), nullable=False)
    availability = db.Column(db.String(200))
    phone = db.Column(db.String(20))
    user = db.relationship('User', backref='doctor', uselist=False)

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor.id'), nullable=False)
    appointment_date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='pending')
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    patient = db.relationship('Patient', backref='appointments')
    doctor = db.relationship('Doctor', backref='appointments')

# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif user.role == 'doctor':
            return redirect(url_for('doctor_dashboard'))
        else:  # patient
            return redirect(url_for('patient_dashboard'))
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, password=hashed_password, role=role)
            db.session.add(new_user)
            db.session.commit()
            if role == 'patient':
                new_patient = Patient(user_id=new_user.id, name=username)
                db.session.add(new_patient)
            elif role == 'doctor':
                new_doctor = Doctor(user_id=new_user.id, name=username, specialization='General')
                db.session.add(new_doctor)
            db.session.commit()
            flash('Signup successful! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('home'))

# Admin Dashboard
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or db.session.get(User, session['user_id']).role != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    
    num_patients = Patient.query.count()
    num_doctors = Doctor.query.count()
    num_appointments = Appointment.query.count()
    appointment_statuses = db.session.query(Appointment.status, db.func.count(Appointment.status)).group_by(Appointment.status).all()
    status_labels = [status for status, count in appointment_statuses]
    status_counts = [count for status, count in appointment_statuses]
    
    return render_template('admin_dashboard.html', 
                          num_patients=num_patients, 
                          num_doctors=num_doctors, 
                          num_appointments=num_appointments,
                          status_labels=status_labels,
                          status_counts=status_counts)

# Patient Management Routes
@app.route('/admin/patients')
def admin_patients():
    if 'user_id' not in session or db.session.get(User, session['user_id']).role != 'admin':
        return redirect(url_for('login'))
    patients = Patient.query.all()
    return render_template('admin_patients.html', patients=patients)

@app.route('/admin/add_patient', methods=['GET', 'POST'])
def admin_add_patient():
    if 'user_id' not in session or db.session.get(User, session['user_id']).role != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        new_user = User(username=username, password=password, role='patient')
        db.session.add(new_user)
        db.session.commit()
        new_patient = Patient(
            user_id=new_user.id,
            name=request.form['name'],
            age=request.form['age'],
            gender=request.form['gender'],
            address=request.form['address'],
            phone=request.form['phone'],
            medical_history=request.form['medical_history']
        )
        db.session.add(new_patient)
        db.session.commit()
        flash('Patient added successfully', 'success')
        return redirect(url_for('admin_patients'))
    return render_template('admin_add_patient.html')

@app.route('/admin/edit_patient/<int:patient_id>', methods=['GET', 'POST'])
def admin_edit_patient(patient_id):
    if 'user_id' not in session or db.session.get(User, session['user_id']).role != 'admin':
        return redirect(url_for('login'))
    patient = db.session.get(Patient, patient_id)
    if not patient:
        flash('Patient not found', 'danger')
        return redirect(url_for('admin_patients'))
    if request.method == 'POST':
        patient.name = request.form['name']
        patient.age = request.form['age']
        patient.gender = request.form['gender']
        patient.address = request.form['address']
        patient.phone = request.form['phone']
        patient.medical_history = request.form['medical_history']
        db.session.commit()
        flash('Patient updated successfully', 'success')
        return redirect(url_for('admin_patients'))
    return render_template('admin_edit_patient.html', patient=patient)

@app.route('/admin/delete_patient/<int:patient_id>')
def admin_delete_patient(patient_id):
    if 'user_id' not in session or db.session.get(User, session['user_id']).role != 'admin':
        return redirect(url_for('login'))
    patient = db.session.get(Patient, patient_id)
    if not patient:
        flash('Patient not found', 'danger')
        return redirect(url_for('admin_patients'))
    user = db.session.get(User, patient.user_id)
    db.session.delete(patient)
    db.session.delete(user)
    db.session.commit()
    flash('Patient deleted successfully', 'success')
    return redirect(url_for('admin_patients'))

# Doctor Management Routes
@app.route('/admin/doctors')
def admin_doctors():
    if 'user_id' not in session or db.session.get(User, session['user_id']).role != 'admin':
        return redirect(url_for('login'))
    doctors = Doctor.query.all()
    return render_template('admin_doctors.html', doctors=doctors)

@app.route('/admin/add_doctor', methods=['GET', 'POST'])
def admin_add_doctor():
    if 'user_id' not in session or db.session.get(User, session['user_id']).role != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        new_user = User(username=username, password=password, role='doctor')
        db.session.add(new_user)
        db.session.commit()
        new_doctor = Doctor(
            user_id=new_user.id,
            name=request.form['name'],
            specialization=request.form['specialization'],
            availability=request.form['availability'],
            phone=request.form['phone']
        )
        db.session.add(new_doctor)
        db.session.commit()
        flash('Doctor added successfully', 'success')
        return redirect(url_for('admin_doctors'))
    return render_template('admin_add_doctor.html')

@app.route('/admin/edit_doctor/<int:doctor_id>', methods=['GET', 'POST'])
def admin_edit_doctor(doctor_id):
    if 'user_id' not in session or db.session.get(User, session['user_id']).role != 'admin':
        return redirect(url_for('login'))
    doctor = db.session.get(Doctor, doctor_id)
    if not doctor:
        flash('Doctor not found', 'danger')
        return redirect(url_for('admin_doctors'))
    if request.method == 'POST':
        doctor.name = request.form['name']
        doctor.specialization = request.form['specialization']
        doctor.availability = request.form['availability']
        doctor.phone = request.form['phone']
        db.session.commit()
        flash('Doctor updated successfully', 'success')
        return redirect(url_for('admin_doctors'))
    return render_template('admin_edit_doctor.html', doctor=doctor)

@app.route('/admin/delete_doctor/<int:doctor_id>')
def admin_delete_doctor(doctor_id):
    if 'user_id' not in session or db.session.get(User, session['user_id']).role != 'admin':
        return redirect(url_for('login'))
    doctor = db.session.get(Doctor, doctor_id)
    if not doctor:
        flash('Doctor not found', 'danger')
        return redirect(url_for('admin_doctors'))
    user = db.session.get(User, doctor.user_id)
    db.session.delete(doctor)
    db.session.delete(user)
    db.session.commit()
    flash('Doctor deleted successfully', 'success')
    return redirect(url_for('admin_doctors'))

# Appointment Management
@app.route('/admin/appointments')
def admin_appointments():
    if 'user_id' not in session or db.session.get(User, session['user_id']).role != 'admin':
        return redirect(url_for('login'))
    appointments = Appointment.query.all()
    return render_template('admin_appointments.html', appointments=appointments)

@app.route('/admin/manage_appointment/<int:appointment_id>/<action>')
def admin_manage_appointment(appointment_id, action):
    if 'user_id' not in session or db.session.get(User, session['user_id']).role != 'admin':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    appointment = db.session.get(Appointment, appointment_id)
    if not appointment:
        flash('Appointment not found', 'danger')
        return redirect(url_for('admin_appointments'))
    if action in ['approve', 'reject'] and appointment.status == 'pending':
        appointment.status = 'accepted' if action == 'approve' else 'rejected'
        db.session.commit()
        flash(f'Appointment {action}d successfully', 'success')
    else:
        flash('Invalid action or appointment status', 'danger')
    return redirect(url_for('admin_appointments'))

# Patient Dashboard
@app.route('/patient_dashboard')
def patient_dashboard():
    if 'user_id' not in session or db.session.get(User, session['user_id']).role != 'patient':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    patient = Patient.query.filter_by(user_id=session['user_id']).first()
    if not patient:
        flash('Patient profile not found', 'danger')
        return redirect(url_for('login'))
    appointments = Appointment.query.filter_by(patient_id=patient.id).all()
    doctors = Doctor.query.all()
    return render_template('patient_dashboard.html', patient=patient, appointments=appointments, doctors=doctors)

@app.route('/book_appointment', methods=['GET', 'POST'])
def book_appointment():
    if 'user_id' not in session or db.session.get(User, session['user_id']).role != 'patient':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    patient = Patient.query.filter_by(user_id=session['user_id']).first()
    doctors = Doctor.query.all()
    if request.method == 'POST':
        doctor_id = request.form['doctor_id']
        appointment_date = datetime.strptime(request.form['appointment_date'], '%Y-%m-%dT%H:%M')
        notes = request.form['notes']
        new_appointment = Appointment(
            patient_id=patient.id,
            doctor_id=doctor_id,
            appointment_date=appointment_date,
            status='pending',
            notes=notes
        )
        db.session.add(new_appointment)
        db.session.commit()
        flash('Appointment booked successfully', 'success')
        return redirect(url_for('patient_dashboard'))
    return render_template('book_appointment.html', patient=patient, doctors=doctors)

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session or db.session.get(User, session['user_id']).role != 'patient':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    patient = Patient.query.filter_by(user_id=session['user_id']).first()
    if not patient:
        flash('Patient profile not found', 'danger')
        return redirect(url_for('login'))
    if request.method == 'POST':
        patient.name = request.form['name']
        patient.age = request.form['age']
        patient.gender = request.form['gender']
        patient.address = request.form['address']
        patient.phone = request.form['phone']
        patient.medical_history = request.form['medical_history']
        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('patient_dashboard'))
    return render_template('edit_profile.html', patient=patient)

@app.route('/cancel_appointment/<int:appointment_id>')
def cancel_appointment(appointment_id):
    if 'user_id' not in session or db.session.get(User, session['user_id']).role != 'patient':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    appointment = db.session.get(Appointment, appointment_id)
    if not appointment:
        flash('Appointment not found', 'danger')
        return redirect(url_for('patient_dashboard'))
    patient = Patient.query.filter_by(user_id=session['user_id']).first()
    if appointment.patient_id != patient.id:
        flash('Unauthorized action', 'danger')
        return redirect(url_for('patient_dashboard'))
    if appointment.status == 'pending':
        db.session.delete(appointment)
        db.session.commit()
        flash('Appointment canceled successfully', 'success')
    else:
        flash('Cannot cancel non-pending appointment', 'danger')
    return redirect(url_for('patient_dashboard'))

# Doctor Dashboard
@app.route('/doctor_dashboard')
def doctor_dashboard():
    if 'user_id' not in session or db.session.get(User, session['user_id']).role != 'doctor':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    doctor = Doctor.query.filter_by(user_id=session['user_id']).first()
    if not doctor:
        flash('Doctor profile not found', 'danger')
        return redirect(url_for('login'))
    appointments = Appointment.query.filter_by(doctor_id=doctor.id).all()
    patient_ids = {app.patient_id for app in appointments}
    patients = Patient.query.filter(Patient.id.in_(patient_ids)).all()
    return render_template('doctor_dashboard.html', doctor=doctor, appointments=appointments, patients=patients)

@app.route('/manage_appointment/<int:appointment_id>/<action>')
def manage_appointment(appointment_id, action):
    if 'user_id' not in session or db.session.get(User, session['user_id']).role != 'doctor':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    appointment = db.session.get(Appointment, appointment_id)
    if not appointment:
        flash('Appointment not found', 'danger')
        return redirect(url_for('doctor_dashboard'))
    doctor = Doctor.query.filter_by(user_id=session['user_id']).first()
    if appointment.doctor_id != doctor.id:
        flash('Unauthorized action', 'danger')
        return redirect(url_for('doctor_dashboard'))
    if action in ['accept', 'reject'] and appointment.status == 'pending':
        appointment.status = 'accepted' if action == 'accept' else 'rejected'
        db.session.commit()
        flash(f'Appointment {action}ed successfully', 'success')
    else:
        flash('Invalid action or appointment status', 'danger')
    return redirect(url_for('doctor_dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', password=generate_password_hash('adminpass'), role='admin')
            db.session.add(admin_user)
            db.session.commit()
        if Patient.query.count() == 0:
            for i in range(1, 3):
                user = User(username=f'patient{i}', password=generate_password_hash('pass'), role='patient')
                db.session.add(user)
                db.session.commit()
                patient = Patient(user_id=user.id, name=f'Patient {i}', age=25+i*5, gender='Male' if i%2 else 'Female', address=f'{i} Main St', phone=f'123456{i}', medical_history='None')
                db.session.add(patient)
            db.session.commit()
        if Doctor.query.count() == 0:
            for i in range(1, 3):
                user = User(username=f'doctor{i}', password=generate_password_hash('pass'), role='doctor')
                db.session.add(user)
                db.session.commit()
                doctor = Doctor(user_id=user.id, name=f'Dr. {i}', specialization='General' if i%2 else 'Cardiology', availability='Mon-Fri 9-5', phone=f'111222{i}')
                db.session.add(doctor)
            db.session.commit()
        if Appointment.query.count() == 0:
            app1 = Appointment(patient_id=1, doctor_id=1, appointment_date=datetime(2024, 10, 1, 10, 0), status='pending')
            app2 = Appointment(patient_id=2, doctor_id=2, appointment_date=datetime(2024, 10, 2, 11, 0), status='accepted')
            db.session.add_all([app1, app2])
            db.session.commit()
    app.run(debug=True)
