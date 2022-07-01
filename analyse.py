"""
tmp = sorted(permission.items(), key=lambda item: item[1][0])
ttt = {key: val for key, val in permission.items() if val[0] == 'dangerous'}
print(ttt)
"""


def analyse(permission):
    result = []
    for i in permission.keys():
        j = permission[i][0]
        if j == 'dangerous':
            result.append(i)
    return result
