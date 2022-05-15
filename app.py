import os
from flask import Flask, request, render_template, \
     flash, redirect, url_for, send_from_directory
from flask_security import Security, current_user, auth_required, \
     hash_password, SQLAlchemySessionUserDatastore
from werkzeug.utils import secure_filename

from config import Config
from database import db_session, init_db
from models import User, Role

ALLOWED_EXTENSIONS = {'txt', 'apk', 'docx'}

SECURITY_LOGIN_USER_TEMPLATE = 'templates/security/login_user.html'
SECURITY_REGISTER_USER_TEMPLATE = 'templates/security/register_user.html'

# Create app
app = Flask(__name__)
app.config.from_object(Config)
app.config['DEBUG'] = True

# Setup Flask-Security
user_datastore = SQLAlchemySessionUserDatastore(db_session, User, Role)
security = Security(app, user_datastore)


@security.login_context_processor
def security_login_processor():
    return dict()


@app.teardown_request
def remove_session(ex=None):
    db_session.remove()


# Create a user to test with
@app.before_first_request
def create_user():
    admin_email = 'admin@me.com'    # TODO вынести в конфиг
    admin_password = 'root'
    init_db()
    user_datastore.find_or_create_role(name='admin', description='администратор')
    user_datastore.find_or_create_role(name='user', description='пользователь')
    db_session.commit()
    if not user_datastore.find_user(email=admin_email):
        user_datastore.create_user(email=admin_email, password=hash_password(admin_password))
        db_session.commit()
        user_datastore.add_role_to_user(user_datastore.find_user(email=admin_email), 'admin')
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
