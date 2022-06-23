import hashlib
import time

import requests
from sqlalchemy import insert, select
import ssdeep
# import scanner.ssdeep as ssdeep

from config import API_KEY
from scanner.db import db_session, Hash, init_db
# from db import db_session, Hash, init_db


# API_KEY = 'd9da36233f2a6d367fc9c7b1389bfd02a1fcc34e1191a77782f3c43db96cf4ef'


def creat_database():
    init_db()
    query = select(Hash.name).limit(1)
    check = db_session.execute(query).fetchone()
    if check is None:
        with open("ssdeep_hash.txt", "r") as f:
            for line in f:
                line = line.strip('\n "')
                insert_query = insert(Hash).values({Hash.name: line})
                db_session.execute(insert_query)
        db_session.commit()


def scan_database(file_hash, sensitivity=80):
    creat_database()
    hash_id_list = db_session.execute(select(Hash.id)).fetchall()
    hash_id_list = [int(i[0]) for i in hash_id_list]
    for hash_id in hash_id_list:
        query = select(Hash.name).where(Hash.id == hash_id)
        db_hash = db_session.execute(query).fetchone()
        result = ssdeep.compare(file_hash, db_hash)
        if result >= sensitivity:
            return True
    return False


def get_file_hash_sha256(file_path):
    block_size = 65536
    result = hashlib.sha256()
    with open(file_path, 'rb') as f:
        fb = f.read(block_size)
        while len(fb) > 0:
            result.update(fb)
            fb = f.read(block_size)
    return result.hexdigest()


def api_find_file(file_sha256):
    url = f'https://www.virustotal.com/api/v3/files/{file_sha256}'
    headers = {
        "Accept": "application/json",
        "x-apikey": API_KEY
    }
    response = requests.get(url, headers=headers)
    response_dict = response.json()
    try:
        return response_dict['data']['attributes']['ssdeep'], response_dict['data']['attributes']['last_analysis_stats']
    except KeyError:
        return '', dict()


def api_upload_file(file_path):
    url = 'https://www.virustotal.com/api/v3/files'
    files = {"file": open(file_path, "rb")}
    headers = {
        "Accept": "application/json",
        "x-apikey": API_KEY
    }
    response = requests.post(url, files=files, headers=headers)
    response_dict = response.json()
    try:
        return response_dict['data']['id']
    except KeyError:
        return ''


def api_analyse_file(file_id):
    url = f'https://www.virustotal.com/api/v3/analyses/{file_id}'
    headers = {
        "Accept": "application/json",
        "x-apikey": API_KEY
    }
    response = requests.get(url, headers=headers)
    response_dict = response.json()
    try:
        return response_dict['data']['attributes']['status']
    except KeyError:
        return ''


def scan(file_path):    # True - вредонос, False - все окей
    hash_sha256 = get_file_hash_sha256(file_path)
    hash_ssdeep, analyse_result = api_find_file(hash_sha256)
    if hash_ssdeep == '':
        file_id = api_upload_file(file_path)
        analyse_status = ''
        while analyse_status != 'completed':
            time.sleep(2)
            analyse_status = api_analyse_file(file_id)
        hash_ssdeep, analyse_result = api_find_file(hash_sha256)

    check_ssdeep = scan_database(hash_ssdeep)
    if check_ssdeep:
        return True
    else:
        check_api = max(analyse_result, key=analyse_result.get)
        if check_api == 'suspicious' or check_api == 'malicious':
            return True

    return False


if __name__ == '__main__':
    # creat_database()

    file_file = r'C:\Users\alina\Desktop\com.github.axet.bookreader_412.apk'
    file_1 = r'C:\Users\alina\Desktop\test.txt'
    file_2 = r'C:\Users\alina\Desktop\not_virus.txt'

    # scan(file_file)
    # scan(file_2)
    scan_database('3:a+JraNvsgzsVqSwHq9:tJuOgzsko')
