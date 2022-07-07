'''
import ssdeep

a = '/home/user/6c8.apk'
a_h = ssdeep.hash_from_file(a)

b = '/home/user/a07.apk'
b_h = ssdeep.hash_from_file(b)
b_h = '393216:H0MN1xjIAbL4d73dW9HL3cd03LCd2jkMRjC4FbKLm9xjXZfL7:HxSAbL4d5qHLMd03OdZCC40Cpf/'

res = ssdeep.compare(a_h, b_h)
print(a_h)
print(b_h)
print(res)
'''

from colorama import Fore, Style

file = '196608:3veWhAO4OFcitjKqtfd+r/bo1E8lBbQcqp5inUFe9yWUKjrJ6JXUHXcuX8AKrRG7:5AYKmoo1h3Cp5iUF1vkr6XsFmE'
db = [
    ('393216:H0MN1xjIAbL4d73dW9HL3cd03LCd2jkMRjC4FbKLm9xjXZfL7:HxSAbL4d5qHLMd03OdZCC40Cpf/', '0'),
    ('196608:bveWhAO4OFcitjKqtfd+r/bo1E8lBbQcqp5inUFe9yWUKjrA6L/XUMXcuX8AKrRE:FAYKmoo1h3Cp5iUF1vkr1/XRFmQ/', '91'),
    ('98304:Vz2v/oOd4+e/h8WBJbiBUUPBnzvU0C/MHpCNnvB:koJ+e/h8WfmBxVRqMJC/', '0')
]

for elem in db:
    print('сигнатура загруженного файла:')
    print(Fore.GREEN + file + Style.RESET_ALL)
    print('сигнатура файла из базы данных:')
    print(Fore.GREEN + elem[0] + Style.RESET_ALL)
    print('схожесть сигнатур: \t' + Fore.GREEN + elem[1] + Style.RESET_ALL)
    print()


"""
base:
a070fcf0b20e1bf5e7572d3c2eae1c68d8efe019b632a539d8f86aa333c36b9f.zip

new:
6c8de4a7836adb66fb878b1fba4f27bad96f9d4824a128c303c987569a54f9f4.zip

196608:bveWhAO4OFcitjKqtfd+r/bo1E8lBbQcqp5inUFe9yWUKjrA6L/XUMXcuX8AKrRE:FAYKmoo1h3Cp5iUF1vkr1/XRFmQ/
196608:3veWhAO4OFcitjKqtfd+r/bo1E8lBbQcqp5inUFe9yWUKjrJ6JXUHXcuX8AKrRG7:5AYKmoo1h3Cp5iUF1vkr6XsFmE
91


75f9f66bcbfb732b3720f9b56a5b56a3a671ff4386b0b7dc8195124b0db206c0
98304:Vz2v/oOd4+e/h8WBJbiBUUPBnzvU0C/MHpCNnvB:koJ+e/h8WfmBxVRqMJC/

2192345562b9fb1536465d31f465015cb8b0a029fa118166de0d6975bd00448b
393216:H0MN1xjIAbL4d73dW9HL3cd03LCd2jkMRjC4FbKLm9xjXZfL7:HxSAbL4d5qHLMd03OdZCC40Cpf/




196608:/r4lU2ceS9+PiGVlMIX+dhSoKKXfdOgGEXbBD6SOfK4HNjl4lQ:/i3BpPF8NKKdJXNDcfTjlD
"""

