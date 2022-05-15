import psycopg2
from psycopg2 import Error

import config_scanner as conf

test = 'a53732f6b49c8d9b99b7bdad38c3255f7ea944e14b86c8f674dd3187c74e808e'

connection, cursor = False, False

try:
    connection = psycopg2.connect(user=conf.USER,
                                  password=conf.PASSWORD,
                                  host=conf.HOST,
                                  port=conf.PORT,
                                  database=conf.DATABASE)

    cursor = connection.cursor()
    insert_query = f"""
    SELECT * FROM sha256
    WHERE sha256.hash LIKE '{test}';
    """
    cursor.execute(insert_query)
    result = cursor.fetchone()
    if result:
        print(result[1])
    # connection.commit()

except (Exception, Error) as error:
    print("Ошибка при работе с PostgreSQL", error)

finally:
    if connection:
        cursor.close()
        connection.close()
        print("Соединение с PostgreSQL закрыто")
