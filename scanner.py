import hashlib
import time

from androguard.core.androconf import show_logging
from androguard.misc import AnalyzeAPK
import requests
from sqlalchemy import insert, select
import ssdeep

from analyse import analyse
from config import API_KEY
from scanner_db import db_session, Hash, init_db


def get_file_hash_sha256(file_path):
    block_size = 65536
    result = hashlib.sha256()
    with open(file_path, 'rb') as f:
        fb = f.read(block_size)
        while len(fb) > 0:
            result.update(fb)
            fb = f.read(block_size)
    print(result.hexdigest())
    return result.hexdigest()


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


def scan_database(file_hash, sensitivity=80, detail: bool = False):
    creat_database()
    hash_id_list = db_session.execute(select(Hash.id)).fetchall()
    hash_id_list = [int(i[0]) for i in hash_id_list]
    for hash_id in hash_id_list:
        query = select(Hash.name).where(Hash.id == hash_id)
        db_hash = db_session.execute(query).fetchone()
        result = ssdeep.compare(file_hash, db_hash)
        if result > 50 and detail:
            print(file_hash, db_hash, result)
        if result >= sensitivity:
            return True
    return False


def api_find_file(file_sha256, detail: bool = False):
    url = f'https://www.virustotal.com/api/v3/files/{file_sha256}'
    headers = {
        "Accept": "application/json",
        "x-apikey": API_KEY
    }
    response = requests.get(url, headers=headers)
    response_dict = response.json()
    ssdeep_hash = ''
    analysis_stats = dict()
    try:
        ssdeep_hash = response_dict['data']['attributes']['ssdeep']
        analysis_stats = response_dict['data']['attributes']['last_analysis_stats']
        if detail:
            print(analysis_stats)
        return ssdeep_hash, analysis_stats
    except KeyError:
        return ssdeep_hash, analysis_stats


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


def analyse_apk(file_path, detail: bool = False):
    print()
    apk_obj, _, _ = AnalyzeAPK(file_path)
    permission = apk_obj.get_details_permissions()
    perm = analyse(permission)
    if detail:
        print(file_path)
        if len(perm) > 0:
            perm.sort()
            print('Найдены опасные права:')
            print(*perm, sep='\n')
        else:
            print('Опасных прав не найдено!:')
    return


# True - вредонос, False - все окей
def scan(file_path):
    hash_sha256 = get_file_hash_sha256(file_path)
    hash_ssdeep, analyse_result = api_find_file(hash_sha256)
    if analyse_result == dict():
        file_id = api_upload_file(file_path)
        analyse_status = ''
        while analyse_status != 'completed':
            analyse_status = api_analyse_file(file_id)
            time.sleep(2)
        hash_ssdeep, analyse_result = api_find_file(hash_sha256)
    check_ssdeep = scan_database(hash_ssdeep)
    if check_ssdeep:
        return True
    else:
        check_api = max(analyse_result, key=analyse_result.get)
        if check_api == 'suspicious' or check_api == 'malicious':
            return True
        else:
            analyse_apk(file_path)
    return False


if __name__ == '__main__':
    print('\n\n\n')

    f_1 = r'C:\Users\alina\Desktop\com.github.axet.bookreader_412.apk'
    f_2 = r'C:\Users\alina\Desktop\eu.faircode.email_1921.apk'

    file_1 = r'C:\Users\alina\Desktop\test.txt'
    file_2 = r'C:\Users\alina\Desktop\not_virus.txt'

    EICAR = '3:a+JraNvsgzsVqSwHq9:tJuOgzsko'

    # creat_database()

    # scan(f_1)
    # scan(f_2)
    # scan(file_1)
    # scan(file_2)

    # get_file_hash_sha256(file_file)

    # scan_database(EICAR)

    show_logging()
    analyse_apk(f_1, detail=True)
    analyse_apk(f_2, detail=True)
