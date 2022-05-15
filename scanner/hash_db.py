import psycopg2
from psycopg2 import Error

import config_scanner as conf


connection, cursor = False, False

try:
    connection = psycopg2.connect(user=conf.USER,
                                  password=conf.PASSWORD,
                                  host=conf.HOST,
                                  port=conf.PORT,
                                  database=conf.DATABASE)
    cursor = connection.cursor()
    insert_query = f"""
    CREATE TABLE IF NOT EXISTS sha256
    (
    id SERIAL PRIMARY KEY,
    hash VARCHAR(70) NOT NULL UNIQUE
    );
    """
    cursor.execute(insert_query)
    connection.commit()
    with open("full_sha256.txt", "r") as f:
        for line in f:
            if '#' in line:
                continue
            line = line.strip('\n')
            insert_query = f"INSERT INTO sha256 (hash) VALUES ('{line}');"
            cursor.execute(insert_query)
    connection.commit()

except (Exception, Error) as error:
    print("Ошибка при работе с PostgreSQL", error)

finally:
    if connection:
        cursor.close()
        connection.close()
        print("Соединение с PostgreSQL закрыто")



