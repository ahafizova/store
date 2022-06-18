import os

basedir = os.path.abspath(os.path.dirname(__file__))
DATABASE_URL = 'postgresql://postgres:root@localhost/app'
# DATABASE_URL = 'sqlite:///' + os.path.join(basedir, 'app.db?charset=utf8')


class Config(object):
    SECRET_KEY = 'bHFLqgZMyCxAVD7FrjHlkemObBcTGDINu1bqZC6LQHo'
    SECURITY_PASSWORD_SALT = '56705562324377679700669174502688436689'
    # SECRET_KEY = secrets.token_urlsafe()
    # SECURITY_PASSWORD_SALT = secrets.SystemRandom().getrandbits(128)

    SECURITY_PASSWORD_HASH = 'sha512_crypt'
    SECURITY_REGISTERABLE = True
    SECURITY_SEND_REGISTER_EMAIL = False
    SECURITY_POST_REGISTER_VIEW = '/home'
    SECURITY_POST_LOGIN_VIEW = '/home'

    # ('Please log in to access this page.', 'info')
    SECURITY_MSG_LOGIN = ('Для доступа к странице войдите в систему', 'info')
    # ('%(email)s is already associated with an account.', 'error')
    SECURITY_MSG_EMAIL_ALREADY_ASSOCIATED = ('%(email)s уже связан с учетной записью', 'error')
    # ('Invalid email address', 'error')
    SECURITY_MSG_INVALID_EMAIL_ADDRESS = ('Неверный адрес электронной почты', 'error')
    # ('Password must be at least %(length)s characters', 'error')
    SECURITY_MSG_PASSWORD_INVALID_LENGTH = ('Пароль должен состоять не менее чем из %(length)s символов', 'error')
    # ('Password not provided', 'error')
    SECURITY_MSG_PASSWORD_NOT_PROVIDED = ('Пароль не указан', 'error')
    # ('Passwords do not match', 'error')
    SECURITY_MSG_RETYPE_PASSWORD_MISMATCH = ('Пароли не совпадают', 'error')

    UPLOAD_FOLDER = os.path.join(basedir, 'file')
    MAX_CONTENT_LENGTH = 128 * 1000 * 1000  # TODO изменить размер
