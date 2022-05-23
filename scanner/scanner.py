from sqlalchemy import insert, select

from db import db_session, Hash, init_db


def creat_database():
    init_db()
    select_query = select(Hash.name).limit(1)
    check = db_session.execute(select_query).fetchone()
    print(check)
    if check is None:
        with open("full_sha256.txt", "r") as f:
            for line in f:
                if '#' in line:
                    continue
                line = line.strip('\n')
                insert_query = insert(Hash).values({Hash.name: line})
                db_session.execute(insert_query)
        db_session.commit()


def file_hash(file_path):  # TODO хеширование файла
    print(file_path)


def scan(file_path):  # TODO поиск по базе
    file_hash(file_path)
    # SELECT * FROM sha256
    # WHERE sha256.hash LIKE '{file_path}';


if __name__ == '__main__':
    creat_database()
