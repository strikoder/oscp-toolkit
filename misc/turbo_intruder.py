from datetime import datetime, timedelta
import os

def queueRequests(target, wordlists=None):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=5,
        requestsPerConnection=100,
        pipeline=False
    )

    # === CONFIG ===
    mode = 1          # 1=wordlist, 2=numeric, 3=date
    wl_choice = 1     # 1=burp-params, 2=LFI-win, 3=LFI-lin, 4=LFI-jhaddix

    seq_start, seq_end = 1, 65535
    start_date = datetime(2010, 1, 1)
    end_date   = datetime(2024, 1, 31)

    # hardcoded mapping
    wordlist_paths = {
        1: '/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt',
        2: '/usr/share/wordlists/LFI-Windows.txt',
        3: '/usr/share/wordlists/LFI-Linux.txt',
        4: '/usr/share/wordlists/LFI-Jhaddix.txt',
    }

    if mode == 1:
        path = wordlist_paths[wl_choice]
        if not os.path.isfile(path):
            raise Exception("Wordlist not found for choice %s: %s" % (wl_choice, path))
        with open(path, 'r') as f:
            for line in f:
                word = line.strip()
                if not word or word.startswith('#'):
                    continue
                engine.queue(target.req, word)

    elif mode == 2:
        for i in range(seq_start, seq_end + 1):
            engine.queue(target.req, str(i))

    elif mode == 3:
        d = start_date
        while d <= end_date:
            engine.queue(target.req, d.strftime('%Y-%m-%d'))
            d += timedelta(days=1)

def handleResponse(req, status):
    if status != 404:
        table.add(req)
