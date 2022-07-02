import ssdeep

a = '/home/user/6c8.apk'
a_h = ssdeep.hash_from_file(a)

b = '/home/user/a07.apk'
b_h = ssdeep.hash_from_file(b)

res = ssdeep.compare(a_h, b_h)
print(a_h)
print(b_h)
print(res)

"""
a070fcf0b20e1bf5e7572d3c2eae1c68d8efe019b632a539d8f86aa333c36b9f.zip
6c8de4a7836adb66fb878b1fba4f27bad96f9d4824a128c303c987569a54f9f4.zip

196608:bveWhAO4OFcitjKqtfd+r/bo1E8lBbQcqp5inUFe9yWUKjrA6L/XUMXcuX8AKrRE:FAYKmoo1h3Cp5iUF1vkr1/XRFmQ/
196608:3veWhAO4OFcitjKqtfd+r/bo1E8lBbQcqp5inUFe9yWUKjrJ6JXUHXcuX8AKrRG7:5AYKmoo1h3Cp5iUF1vkr6XsFmE
91
"""

