from flask import Flask, render_template, request,send_file, session, redirect, url_for
from cryptography.fernet import Fernet
import os

app = Flask(__name__)
from flask_sqlalchemy import SQLAlchemy

app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(100), nullable=False)

    filename = db.Column(db.String(200), nullable=False)

    action = db.Column(db.String(50), nullable=False)

    timestamp = db.Column(
        db.DateTime,
        default=db.func.current_timestamp()
    )
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Load encryption key
with open(os.path.join(BASE_DIR, "secret.key"), "rb") as key_file:
    key = key_file.read()

fernet = Fernet(key)

@app.route('/')
def home():

    if 'username' not in session:
        return redirect(url_for('login'))

    user_folder = os.path.join(
        UPLOAD_FOLDER,
        session['username']
    )

    os.makedirs(user_folder, exist_ok=True)

    total_files = len([
        f for f in os.listdir(user_folder)
        if f.endswith(".encrypted")
    ])

    return render_template(
        'index.html',
        username=session['username'],
        total_files=total_files
    )
@app.route('/upload', methods=['POST'])
def upload_file():

    if 'username' not in session:
        return redirect(url_for('login'))

    file = request.files['file']

    if file.filename == '':
        return "No file selected"

    # Create folder for logged-in user
    user_folder = os.path.join(
        UPLOAD_FOLDER,
        session['username']
    )

    os.makedirs(user_folder, exist_ok=True)

    file_data = file.read()

    encrypted_data = fernet.encrypt(file_data)

    encrypted_filename = file.filename + ".encrypted"

    filepath = os.path.join(
        user_folder,
        encrypted_filename
    )

    with open(filepath, "wb") as f:
        f.write(encrypted_data)

    log = ActivityLog(
        username=session['username'],
        filename=encrypted_filename,
        action="Upload"
    )

    db.session.add(log)
    db.session.commit()

    return "File uploaded successfully!"
@app.route('/files')
def files():

    if 'username' not in session:
        return redirect(url_for('login'))

    user_folder = os.path.join(
        UPLOAD_FOLDER,
        session['username']
    )

    os.makedirs(user_folder, exist_ok=True)

    files = [
        f for f in os.listdir(user_folder)
        if f.endswith(".encrypted")
    ]

    return render_template(
        'files.html',
        files=files
    )
@app.route('/download/<filename>')
def download_file(filename):

    # Check if user is logged in
    if 'username' not in session:
        return redirect(url_for('login'))

    # Security check
    if not filename.endswith(".encrypted"):
        return "Invalid file type"

    # Get current user's folder
    user_folder = os.path.join(
        UPLOAD_FOLDER,
        session['username']
    )

    # Full path of encrypted file
    filepath = os.path.join(
        user_folder,
        filename
    )

    # Check whether file exists
    if not os.path.exists(filepath):
        return "File not found"

    # Read encrypted file
    with open(filepath, "rb") as f:
        encrypted_data = f.read()

    # Decrypt data
    decrypted_data = fernet.decrypt(encrypted_data)

    # Remove .encrypted extension
    original_name = filename.replace(".encrypted", "")

    # Create temporary decrypted file
    temp_path = os.path.join(
        user_folder,
        "temp_" + original_name
    )

    with open(temp_path, "wb") as f:
        f.write(decrypted_data)
    log = ActivityLog(
        username=session['username'],
        filename=filename,
        action="Download"
    )

    db.session.add(log)
    db.session.commit()

    # Send original file to user
    return send_file(
        temp_path,
        as_attachment=True,
        download_name=original_name
    )
@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        new_user = User(
            username=username,
            password=password
        )

        db.session.add(new_user)
        db.session.commit()

        return "Registration Successful!"

    return render_template('register.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(
            username=username,
            password=password
        ).first()

        if user:
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return "Invalid Username or Password"

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/delete/<filename>')
def delete_file(filename):

    if 'username' not in session:
        return redirect(url_for('login'))

    filepath = os.path.join(UPLOAD_FOLDER, filename)

    if os.path.exists(filepath):
        os.remove(filepath)

    log = ActivityLog(
        username=session['username'],
        filename=filename,
        action="Delete"
    )

    db.session.add(log)
    db.session.commit()
    return redirect(url_for('files'))
@app.route('/logs')
def logs():

    if 'username' not in session:
        return redirect(url_for('login'))

    logs = ActivityLog.query.filter_by(
        username=session['username']
    ).all()

    return render_template(
        'logs.html',
        logs=logs
    )
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)