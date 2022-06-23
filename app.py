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
    roles_accepted,
    roles_required,
    Security,
    SQLAlchemySessionUserDatastore,
)
from sqlalchemy import insert, select, update

from config import ADMIN_EMAIL, ADMIN_PASSWORD, Config
from database import db_session, init_db
from models import EntriesUsers, Entry, Role, User
from scanner.scanner import scan

ALLOWED_EXTENSIONS = {'apk', 'txt'}     # TODO изменить потом
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


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@security.login_context_processor
def security_login_processor():
    return dict()


@app.teardown_request
def remove_session(ex=None):
    db_session.remove()


@app.before_first_request
def create_user():
    admin_email = ADMIN_EMAIL
    admin_password = ADMIN_PASSWORD
    init_db()
    user_datastore.find_or_create_role(name='admin', description='администратор')
    user_datastore.find_or_create_role(name='developer', description='разработчик')
    user_datastore.find_or_create_role(name='user', description='пользователь')
    db_session.commit()
    if not user_datastore.find_user(email=admin_email):
        user_datastore.create_user(email=admin_email, password=hash_password(admin_password))
        db_session.commit()

        admin_id = user_datastore.find_user(email=admin_email)
        user_datastore.add_role_to_user(admin_id, 'admin')
        db_session.commit()
        db_session.execute(update(User).where(User.id == admin_id.id).values(name='admin'))
        db_session.commit()


# Views
@app.route('/')
def show_entries():
    search_text = request.args.get('text', default=None, type=str)
    flag = request.args.get('triggered', default=0, type=int)

    if search_text and search_text.strip() != "":
        s = f'%{search_text}%'
        query = select([Entry.title, Entry.tagline, Entry.id]).where(
            Entry.title.ilike(s) | Entry.tagline.ilike(s))
        entries = db_session.execute(query).fetchall()

    else:
        query = select([Entry.title, Entry.tagline, Entry.id]).order_by(Entry.id)
        entries = db_session.execute(query).fetchall()

    if not search_text and not flag:
        if isinstance(current_user, User):
            return render_template('show_entries.html', entries=entries, email=current_user.email)
        else:
            return render_template('show_entries.html', entries=entries)

    return json.dumps(dict(result=[dict(r) for r in entries]))


@app.route('/app/<name>', methods=['GET', 'POST'])
def show(name):
    if request.method == 'POST' and isinstance(current_user, User):
        if request.form["rating"].isdigit():
            query = select([Entry.score]).where(Entry.id == name)
            db_response = db_session.execute(query).fetchone()
            score_dict = json.loads(db_response[0])
            score_dict[f'{current_user.id}'] = int(request.form["rating"])
            score_str = json.dumps(score_dict)
            db_session.execute(update(Entry).where(Entry.id == name).values(score=score_str))
            db_session.commit()

    query = select([Entry.id, Entry.title, Entry.text, Entry.path, Entry.score, Entry.download]).where(
        Entry.id == name)
    entry = db_session.execute(query).fetchone()
    title = entry.title
    text = entry.text.replace('\n', '<br>')
    path = entry.path
    score_dict = json.loads(entry.score)
    amount = round((sum(score_dict.values()) / len(score_dict)), 2)
    download = entry.download

    dev_id = db_session.execute(select([EntriesUsers.user_id]).where(EntriesUsers.entry_id == name)).fetchone()[0]
    dev = db_session.execute(select([User.name]).where(User.id == dev_id)).fetchone()[0]

    response = {
        'id': name,
        'title': title,
        'text': text,
        'path': path,
        'score': amount,
        'download': download,
        'dev': dev
    }

    if isinstance(current_user, User):
        user_score = 0
        user_id = f'{current_user.id}'
        if user_id in score_dict.keys():
            user_score = score_dict[user_id]
        return render_template('show.html', entry=response, email=current_user.email, user_score=user_score,)
    else:
        return render_template('show.html', entry=response)


@app.route('/download/<name>')
def download_file(name):
    load = db_session.execute(select([Entry.download]).where(Entry.path == name)).fetchone()[0] + 1
    db_session.execute(update(Entry).where(Entry.path == name).values(download=load))
    db_session.commit()
    path = os.path.join(app.config["UPLOAD_FOLDER"], name[:LENGTH_FOLDER_NAME])
    return send_from_directory(path, name)


@app.route('/home')
@auth_required()
def home():
    if current_user.has_role('admin') or current_user.has_role('developer'):
        dev = db_session.execute(select([User.name]).where(User.id == current_user.id)).fetchone()[0]
        return render_template('home.html', email=current_user.email, dev=dev)

    return render_template('home_user.html', email=current_user.email)


@app.route('/dev', methods=['GET', 'POST'])     # TODO ограничить доступ по ссылке
@auth_required()
def add_dev():
    if request.method == 'POST':
        dev_name = (request.form["title"])
        query = select([User.id]).where(User.name == dev_name)
        check = db_session.execute(query).fetchone()
        if check:
            flash('Введенное имя уже занято')
            return redirect(request.url)

        user_datastore.add_role_to_user(current_user, 'developer')
        db_session.commit()
        query = update(User).where(User.id == current_user.id).values(name=dev_name)
        db_session.execute(query)
        db_session.commit()

        flash('Вы стали разработчиком')
        return redirect(url_for('home'))

    return render_template('add_dev.html', email=current_user.email)


@app.route('/add', methods=['GET', 'POST'])
def add_entry():
    if not (current_user.has_role('admin') or current_user.has_role('developer')):
        flash('Вы не можете загружать приложения, т.к. не являетесь разработчиком')
        return redirect(url_for('show_entries'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Ошибка')  # No file part
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
            abs_path = os.path.join(user_path, filename)
            file.save(abs_path)    # TODO проверить безопасность файла
            # print('\nabs_path \t', abs_path)
            if scan(abs_path):
                os.remove(abs_path)
                flash('Файл может содержать вредоносные функции')
                return redirect(request.url)
            text = request.form["text"]
            tmp = text + '\n'
            tagline_list = tmp[:250]
            index = []
            for symbol in ['.', '!', '?', '\n']:
                result = tagline_list.find(symbol)
                if result > 0:
                    index.append(result)
            if len(index) > 0:
                tagline = tagline_list[:min(index)+1]
            else:
                tagline = tagline_list[:100]

            new_entry_id = db_session.execute(insert(Entry).values(
                {
                    Entry.title: request.form["title"],
                    Entry.text: text,
                    Entry.tagline: tagline,
                    Entry.path: filename
                }))
            new_entry_id = new_entry_id.inserted_primary_key[0]
            print('new_entry_id \t', new_entry_id)
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


@app.route('/edit')
@auth_required()
@roles_accepted('admin', 'developer')
def edit():
    user_entries = db_session.execute(select([EntriesUsers.entry_id]).where(
        EntriesUsers.user_id == current_user.id)).fetchall()
    entries = []
    for i in user_entries:
        query = select([Entry.id, Entry.title, Entry.text, Entry.path]).where(Entry.id == i[0])
        tmp = db_session.execute(query).fetchone()
        entries.append(tmp)
    return render_template('edit.html', entries=entries, email=current_user.email)


@app.route('/edit/<app_id>')  # TODO добавить редактирование названия, описания и файла
@auth_required()
@roles_accepted('admin', 'developer')
def edit_entry(app_id):
    user_entries = db_session.execute(select([EntriesUsers.entry_id]).where(
        EntriesUsers.user_id == current_user.id)).fetchall()
    if app_id.isdigit():
        if (int(app_id), ) in user_entries:
            entry = db_session.execute(select([Entry.title, Entry.text, Entry.path]).where(
                Entry.id == app_id)).fetchone()
            return render_template('edit_entry.html', entry=entry, email=current_user.email)
    return redirect(url_for('show_entries'))


@app.route('/admin')  # TODO добавить настройки для админа
@auth_required()
@roles_required('admin')
def admin():
    return render_template('admin.html', email=current_user.email)


if __name__ == '__main__':
    app.run()
