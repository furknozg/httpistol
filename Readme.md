██╗░░██╗████████╗████████╗██████╗░██╗░██████╗████████╗░█████╗░██╗░░░░░
██║░░██║╚══██╔══╝╚══██╔══╝██╔══██╗██║██╔════╝╚══██╔══╝██╔══██╗██║░░░░░
███████║░░░██║░░░░░░██║░░░██████╔╝██║╚█████╗░░░░██║░░░██║░░██║██║░░░░░
██╔══██║░░░██║░░░░░░██║░░░██╔═══╝░██║░╚═══██╗░░░██║░░░██║░░██║██║░░░░░
██║░░██║░░░██║░░░░░░██║░░░██║░░░░░██║██████╔╝░░░██║░░░╚█████╔╝███████╗

What is HTTPistol:
    HTTPistol is a python written command line interface to execute a determined attack vector. From http requests, determined by you.
    Main attack vector in this purpose is for blind injections. With threaded requests optimized as much as I personally can with my knowledge.

Purpose:
    The main purpose is to find db names but it could be used for blind injection attacks of many kinds.
    In the future there may be a module for standard injection attacks as well but for now that is on hold.

Usage:
    [python3 httpistol.py & -url "https://example.com/" & -hitclause ">example<" & -payload "injectioncode?{payload}?injectioncode"]

Optional parameters: [-v || -tst 0.1ms || -charset loc.txt]

Parameters:
-url (required): 
    Specifies the url of the request payloads being sent to.
-hitclause (required): 
    Specifies either a phrase or regex which will be looked for in the requests' response.
    The response of a positive blind injection can be different for many systems so the user has to specify
-payload (required):
    Specifies both the injection and the payload area in the request.
    Example: "/?search=admin'%26%26this.password.match(/^?{}?.*/)%00" (an example of a mongodb blind password brute force payload)
        The "?{}?" specifies the area where the wordlist will try to brute force the keyword
        This means specifying the payload area as "?{adm}?" will mean that the program will assume
        adm is the first 3 words of the payload (If keyword+charset[i] does not satisfy a hit for any i in len(charset), the program will exit)
-tst (optional):
    Specifies the thread timing for each request thread. The shorter this is, the more request/seconds you have (use with caution).
    Warning: default value of -tst is 0.09, if your hardware can support faster thread openings you can shorten it. But nevertheless
    most remote servers will most probably block requests that are coming faster than 0.09 ms from one IP.
-charset (optional):
    Specifies an override for the default charset (ascii letters and numbers and also "-")
    Create or use an existing wordlist location and put it in the parameter to use.
        
Creating your own wordlists: 
            each newline specifies a new index so 5\n6\n7 is interpreted as ["5","6","7"].
    -v (optional):
        Verbosity. (Work in progress)



Important notice: 
    The program assumes the injection code you execute is true. So In the worst case you will send requests as much as your wordlist/charset has once and exit
    The threading may be unstable at times, therefore the -tst parameter should only be upped if your hardware can handle it.
    The wordlist can be long but the longer it is, the more thread unsafe it can be. On average the threads working at same time is between 4-5 (-tst 0.09)
    But the program is not meant for phrases yet just characters, although feel free to test it out.
    The use of this code is your own responsibility, I neither do or condone any malicious action taken by any of my code.
