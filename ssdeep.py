HASH_SSDEEP = '3:a+JraNvsgzsVqSwHq9:tJuOgzsko'


def hash_from_file(file_path):
    return HASH_SSDEEP


def compare(hash1, hash2):
    if hash1 == HASH_SSDEEP:
        return 100
    if hash1 == hash2:
        return 100
    else:
        return 0
