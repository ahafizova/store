import os

basedir = os.path.abspath(os.path.dirname(__file__))
DATABASE_URL = 'sqlite:///' + os.path.join(basedir, 'app_2.db')


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

    UPLOAD_FOLDER = os.path.join(basedir, 'file')
    MAX_CONTENT_LENGTH = 128 * 1000 * 1000      # TODO изменить размер
