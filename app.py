import json
import os
import uuid

from flask import (
    flash,
    Flask,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from flask_security import (
    auth_required,
    current_user,
    hash_password,
    roles_required,
    Security,
    SQLAlchemySessionUserDatastore,
)
from sqlalchemy import insert, select

from config import Config
from database import db_session, init_db
from models import EntriesUsers, Entry, Role, User


ALLOWED_EXTENSIONS = {'apk', 'txt', 'docx'}
LENGTH_FOLDER_NAME = 2

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


@app.before_first_request
def create_user():
    admin_email = 'admin@me.com'    # TODO вынести в конфиг ?
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
@app.route('/')     # TODO прикрутить подстраницы
def show_entries():
    search_text = request.args.get('text', default=None, type=str)
    flag = request.args.get('triggered', default=0, type=int)

    if search_text and search_text.strip() != "":
        s = f'%{search_text}%'
        query_select = select([Entry.title, Entry.text, Entry.path]).where(
            Entry.title.ilike(s) | Entry.text.ilike(s))
        entries = db_session.execute(query_select).fetchall()

    else:
        query_select = select([Entry.title, Entry.text, Entry.path]).order_by(Entry.id)
        entries = db_session.execute(query_select).fetchall()

    if not search_text and not flag:
        if isinstance(current_user, User):
            return render_template('show_entries.html', entries=entries, email=current_user.email)
        else:
            return render_template('show_entries.html', entries=entries)

    return json.dumps(dict(result=[dict(r) for r in entries]))      # TODO доделать емаил


@app.route('/home')
@auth_required()
def home():
    return render_template('home.html', email=current_user.email)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/add', methods=['GET', 'POST'])
@auth_required()
def add_entry():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Ошибка')                 # TODO зачем?  No file part
            return redirect(request.url)

        file = request.files['file']

        if file.filename == '':
            flash('Файл не выбран')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            _, expansion = os.path.splitext(file.filename)
            while True:
                filename = f'{uuid.uuid4()}{expansion}'
                file_id = db_session.execute(select([Entry.id]).where(
                    Entry.path == filename)).fetchone()
                if file_id is None:
                    break

            user_path = os.path.join(app.config['UPLOAD_FOLDER'], filename[:LENGTH_FOLDER_NAME])
            if not os.path.exists(user_path):
                os.mkdir(user_path)
            file.save(os.path.join(user_path, filename))

            new_entry_id = db_session.execute(insert(Entry).values(
                {
                    Entry.title: request.form["title"],
                    Entry.text: request.form["text"],
                    Entry.path: filename
                })).lastrowid
            db_session.commit()
            db_session.execute(insert(EntriesUsers).values(
                {
                    EntriesUsers.entry_id: new_entry_id,
                    EntriesUsers.user_id: current_user.id
                }
            ))
            db_session.commit()
            flash('Приложение успешно опубликованно')
            return redirect(url_for('show_entries'))

    return render_template('add_entry.html', error=None, email=current_user.email)


@app.route('/download/<name>')
@auth_required()
def download_file(name):
    path = os.path.join(app.config["UPLOAD_FOLDER"], name[:LENGTH_FOLDER_NAME])
    return send_from_directory(path, name)


@app.route('/store')    # TODO добавить настройки для админа
@auth_required()
@roles_required('admin')
def index():
    return render_template('index.html', email=current_user.email)


@app.route('/edit')     # TODO добавить редактирование названия, описания и файла
@auth_required()
def edit_entry():
    user_entries = db_session.execute(select([EntriesUsers.entry_id]).where(
        EntriesUsers.user_id == current_user.id)).fetchall()
    entries = []
    for i in user_entries:
        query_select = select([Entry.title, Entry.text, Entry.path]).where(Entry.id == i[0])
        tmp = db_session.execute(query_select).fetchone()
        entries.append(tmp)
    return render_template('edit_entry.html', entries=entries, email=current_user.email)


if __name__ == '__main__':
    app.run()
