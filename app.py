import os
from flask import Flask, request, render_template, \
     flash, redirect, url_for, send_from_directory
from flask_security import Security, current_user, auth_required, \
     hash_password, SQLAlchemySessionUserDatastore
from werkzeug.utils import secure_filename

import config_app
from database import db_session, init_db
from models import User, Role

UPLOAD_FOLDER = 'file'
ALLOWED_EXTENSIONS = {'txt', 'apk', 'docx'}

# Create app
app = Flask(__name__)
app.config['DEBUG'] = True

app.config['SECRET_KEY'] = config_app.SECRET_KEY
app.config['SECURITY_PASSWORD_SALT'] = config_app.SECURITY_PASSWORD_SALT
app.config['SECURITY_PASSWORD_HASH'] = config_app.SECURITY_PASSWORD_HASH

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 128 * 1000 * 1000     # TODO изменить размер

app.config['SECURITY_REGISTERABLE'] = True
app.config['SECURITY_SEND_REGISTER_EMAIL'] = False
app.config['SECURITY_POST_LOGIN_VIEW'] = '/home'
app.config['SECURITY_POST_REGISTER_VIEW'] = '/home'

# Setup Flask-Security
user_datastore = SQLAlchemySessionUserDatastore(db_session, User, Role)
security = Security(app, user_datastore)

SECURITY_LOGIN_USER_TEMPLATE = 'templates/security/login_user.html'
SECURITY_REGISTER_USER_TEMPLATE = 'templates/security/register_user.html'


@security.login_context_processor
def security_login_processor():
    return dict()


# Create a user to test with
@app.before_first_request
def create_user():
    init_db()
    if not user_datastore.find_user(email="test@me.com"):
        user_datastore.create_user(email="test@me.com", password=hash_password("password"))
    db_session.commit()


# Views
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/home')
@auth_required()
def home():
    return render_template('home.html', email=current_user.email)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/upload', methods=['GET', 'POST'])
@auth_required()
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('download_file', name=filename))
    return render_template('upload.html')


@app.route('/upload/<name>')
@auth_required()
def download_file(name):
    return send_from_directory(app.config["UPLOAD_FOLDER"], name)


if __name__ == '__main__':
    app.run()
