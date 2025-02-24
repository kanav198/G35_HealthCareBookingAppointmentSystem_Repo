from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required,current_user
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
# Initialize Flask app
app = Flask(__name__)

# Configure secret key and session type
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a random secret key
app.config['SESSION_TYPE'] = 'filesystem'

# Configure SQLAlchemy for SQLite (change URI if using other databases)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///healthcare.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Flask-Session and SQLAlchemy
Session(app)
db = SQLAlchemy(app)

# User Model (ORM)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    dob = db.Column(db.String(10), nullable=False)  # Can be adjusted to Date type if needed
    password = db.Column(db.String(200), nullable=False)  # Hashed password                                                                                
    appointments = db.relationship('Appointment', backref='patient', lazy=True)   # Define a relationship to the Appointment model

class Doctor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Response(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(120), nullable=False)  # Fixed typo
    new_date = db.Column(db.String(200), nullable=False)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointment.id'), nullable=True)  # Optional

# Appointment Model (ORM)
class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    doctor_id = db.Column(db.Integer, nullable=False)  # Assuming doctor_id is known
    requested_date = db.Column(db.String(10), nullable=False)  # Can be adjusted to Date type if needed
    status = db.Column(db.String(20), default='Pending')  # Pending, Accepted, Rejected, Rescheduled
    new_date = db.Column(db.String(10), nullable=True)  # New date proposed by the doctor
 
 
 
with app.app_context():
    db.create_all()
# Create tables
# def create_tables():
  

# create_tables()

@app.route('/')
def index():
    return render_template('homepage.html')  # Main page (Home)

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['firstName']
        last_name = request.form['lastName']
        email = request.form['email']
        phone = request.form['phone']
        dob = request.form['dob']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists!', 'danger')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(first_name=first_name, last_name=last_name, email=email, phone=phone, dob=dob, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_email'] = user.email
            flash('Logged in successfully!', 'success')
            return redirect(url_for('patient_page'))
        else:
            flash('Invalid login credentials. Please try again.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

# Patient page route
@app.route('/patientpage')
def patient_page():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])  # Get user details from the database
        return render_template('patientpage.html', user=user)  # Pass the user object to the template
    else:
        flash('You need to log in first!', 'danger')
        return redirect(url_for('login'))


@app.route('/doclog')
def doclog():
    return render_template('logindoctorpage.html')

# Book appointment route
@app.route('/searchbar', methods=['GET','POST'])

def searchbar():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        query = request.args.get('query', '')
        return render_template('searchbar.html', query=query)
    else:
        flash('You need to log in first!', 'danger')
        return redirect(url_for('login'))

@app.route('/doctordes',methods=['GET','POST'])
def doctordes():
    return render_template('doctordescription.html')

@app.route('/doctordescription_2nd',methods=['GET','POST'])
def doctordescription_2nd():
    return render_template('2nddocdesc.html')

@app.route('/doctordescription_3rd',methods=['GET','POST'])
def doctordescription_3rd():
    return render_template('3rddocdesc.html')

# Request appointment route
@app.route('/request_appointment', methods=['POST'])
def request_appointment():
    if 'user_id' not in session:
        flash('You need to log in first!', 'danger')
        return redirect(url_for('login'))

    requested_date = request.form['requested_date']
    doctor_id = request.form['doctor_id']
    patient_id = session['user_id']

    new_appointment = Appointment(patient_id=patient_id, doctor_id=doctor_id, requested_date=requested_date)
    db.session.add(new_appointment)
    db.session.commit()

    flash('Appointment requested successfully!', 'success')
    return redirect(url_for('patient_page'))


# @app.route('/update_appointment/<int:appointment_id>', methods=['POST'])
# def update_appointment(appointment_id):
#     if 'user_id' not in session:
#         flash('You need to log in first!', 'danger')
#         return redirect(url_for('login'))

#     appointment = Appointment.query.get_or_404(appointment_id)
#     status = request.form['status']
#     new_date = request.form.get('new_date', None)

#     appointment.status = status
#     if status == 'Rescheduled' and new_date:
#         appointment.new_date = new_date

#     db.session.commit()

#     flash('Appointment updated successfully!', 'success')
#     return redirect(url_for('doctor_book'))  # Redirect to the doctor booking page


@app.route('/update_appointment/<int:appointment_id>', methods=['POST'])
def update_appointment(appointment_id):
    if 'doctor_id' not in session:
        flash('You need to log in as a doctor first!', 'danger')
        return redirect(url_for('doclog'))

    logger.debug(f"Updating appointment ID: {appointment_id}")
    logger.debug(f"Form data: {request.form}")

    appointment = Appointment.query.get_or_404(appointment_id)
    status = request.form.get('status')
    new_date = request.form.get('new_date')

    appointment.status = status
    if status == 'Rescheduled' and new_date:
        appointment.new_date = new_date
    elif status != 'Rescheduled':
        appointment.new_date = None

    try:
        db.session.commit()
        logger.debug(f"Updated appointment {appointment_id}: status={appointment.status}, new_date={appointment.new_date}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to update appointment: {str(e)}")
        flash('Failed to update appointment.', 'danger')

    flash('Appointment updated successfully!', 'success')
    return redirect(url_for('doctor_book'))



@app.route('/doctordescription_4th',methods=['GET','POST'])
def doctordescription_4th():
    return render_template('4thdocdesc.html')

@app.route('/doctordescription_5th',methods=['GET','POST'])
def doctordescription_5th():
    return render_template('5thdocdesc.html')

# Logout route
# Logout route
@app.route('/logout', methods=['POST'])  # Change to accept POST requests
def logout():
    session.pop('user_id', None)
    session.pop('user_email', None)
    flash('You have been logged out successfully.', 'info')
    return '', 204  # Return no content


@app.route('/response')
def response():
    status = request.args.get('status')
    new_date = request.args.get('new_date')
    
    # Only create a Response if both parameters are provided
    if status and new_date:
        new_response = Response(status=status, new_date=new_date)
        db.session.add(new_response)
        db.session.commit()

    return render_template('response.html', status=status, new_date=new_date)



@app.route('/user_appointments')
def user_appointments():
    if 'user_id' not in session:
        flash('You need to log in first!', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    appointments = Appointment.query.filter_by(patient_id=user_id).all()
    return render_template('user_appointments.html', appointments=appointments)


@app.route('/register_doctor', methods=['GET', 'POST'])
def register_doctor():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check if the doctor already exists
        doctor = Doctor.query.filter_by(email=email).first()
        if doctor:
            flash('Doctor with this email already exists!', 'danger')
            return redirect(url_for('register_doctor'))

        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Create a new doctor
        new_doctor = Doctor(email=email, password=hashed_password)
        db.session.add(new_doctor)
        db.session.commit()

        flash('Doctor registered successfully!', 'success')
        return redirect(url_for('doclog'))  # Redirect to the doctor login page

    return render_template('register_doctor.html')

# Doctor Login Page


# Doctor Login Form Submission
@app.route('/doctor_login', methods=['POST'])
def doctor_login():
    email = request.form['email']
    password = request.form['password']
    
    # Check if the doctor exists
    doctor = Doctor.query.filter_by(email=email).first()
    
    if doctor and check_password_hash(doctor.password, password):
        session['doctor_id'] = doctor.id  # Store doctor_id in session
        flash('Logged in successfully!', 'success')
        return redirect(url_for('doctor_book'))  # Redirect to doctor booking page
    else:
        flash('Invalid login credentials. Please try again.', 'danger')
        return redirect(url_for('doclog'))  # Redirect back to the doctor login page

# Doctor Booking Page
@app.route('/doctor_book')
def doctor_book():
    if 'doctor_id' not in session:
        flash('You need to log in first!', 'danger')
        return redirect(url_for('doclog'))
    
    doctor_id = session['doctor_id']
    logger.debug(f"Doctor ID from session: {doctor_id}")
    
    # Fetch all appointments, joining with User for patient details
    appointments = Appointment.query.join(User, Appointment.patient_id == User.id).all()
    logger.debug(f"Found {len(appointments)} appointments")
    for appt in appointments:
        logger.debug(f"Appointment {appt.id}: doctor_id={appt.doctor_id}, patient={appt.patient.first_name} {appt.patient.last_name}, status={appt.status}, requested_date={appt.requested_date}, new_date={appt.new_date}")

    return render_template('doctor_book.html', appointments=appointments)

# Logout Route
@app.route('/doctor_logout')
def doctor_logout():
    session.pop('doctor_id', None)  # Remove doctor_id from session
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('doclog'))  # Redirect to the doctor login page



# Run the Flask app


if __name__ == '__main__':
    app.run(debug=True)