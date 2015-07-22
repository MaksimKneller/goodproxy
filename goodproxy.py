""" A multithreaded proxy checker

Given a file containing proxies, per line, in the form of ip:port, will attempt
to establish a connection through each proxy to a provided URL. Duration of connection
attempts is governed by a passed in timeout value. Additionally, spins off a number
of daemon threads to speed up processing using a passed in threads parameter. Proxies
that passed the test are written out to a file called results.txt

Usage:

    goodproxy.py [-h] -file FILE -url URL [-timeout TIMEOUT] [-threads THREADS]
    
Parameters:

    -file    -- filename containing a list of ip:port per line
    -url     -- URL to test connections against
    -timeout -- how long to attempt connecting before marking that proxy as bad (default 1.0)
    -threads -- number of threads to spin off to speed up processing (default 16)

Functions:

    get_proxy_list_size  -- returns the current size of the Queue holding a list of proxies
    testproxy            -- does the actual connecting to the URL via a proxy
    main                 -- loads the proxy file, creates daemon threads, write results to a file
"""
import argparse
import queue
import socket
import sys
import threading
import time
import urllib.request


def get_proxy_list_size(proxylistq):
    """ Return the current Queue size holding a list of proxy ip:ports """

    return proxylistq.qsize()


def testproxy(url, url_timeout, proxylistq, lock, goodproxies, badproxies):
    """ Attempt to establish a connection to a passed in URL through a proxy.

    This function is used in a daemon thread and will loop continuously while waiting for available
    proxies in the proxylistq. Once proxylistq contains a proxy, this function will extract
    that proxy. This action automatically lock the queue until this thread is done with it.
    Builds a urllib.request opener and configures it with the proxy. Attempts to open the URL and
    if successsful then saves the good proxy into the goodproxies list. If an exception is thrown,
    writes the bad proxy to a bodproxies list. The call to task_done() at the end unlocks the queue
    for further processing.

    """

    while True:

        # take an item from the proxy list queue; get() auto locks the
        # queue for use by this thread
        proxyip = proxylistq.get()

        # configure urllib.request to use proxy
        proxy = urllib.request.ProxyHandler({'http': proxyip})
        opener = urllib.request.build_opener(proxy)
        urllib.request.install_opener(opener)

        # some sites block frequent querying from generic headers
        request = urllib.request.Request(
            url, headers={'User-Agent': 'Proxy Tester'})

        try:
            # attempt to establish a connection
            urllib.request.urlopen(request, timeout=float(url_timeout))

            # if all went well save the good proxy to the list
            with lock:
                goodproxies.append(proxyip)

        except (urllib.request.URLError, urllib.request.HTTPError, socket.error):

            # handle any error related to connectivity (timeouts, refused
            # connections, HTTPError, URLError, etc)
            with lock:
                badproxies.append(proxyip)

        finally:
            proxylistq.task_done()  # release the queue


def main(argv):
    """ Main Function

    Uses argparse to process input parameters. File and URL are required while the timeout
    and thread values are optional. Uses threading to create a number of daemon threads each
    of which monitors a Queue for available proxies to test. Once the Queue begins populating,
    the waiting daemon threads will start picking up the proxies and testing them. Successful
    results are written out to a results.txt file.

    """

    proxylistq = queue.Queue()  # Hold a list of proxy ip:ports
    lock = threading.Lock()  # locks goodproxies, badproxies lists
    goodproxies = []    # proxies that passed connectivity tests
    badproxies = []    # proxies that failed connectivity tests

    # Process input parameters
    parser = argparse.ArgumentParser(description='Proxy Checker')

    parser.add_argument(
        '-file', help='a text file with a list of proxy:port per line', required=True)
    parser.add_argument(
        '-url', help='URL for connection attempts', required=True)
    parser.add_argument(
        '-timeout',
        type=float, help='timeout in seconds (defaults to 1', default=1)
    parser.add_argument(
        '-threads', type=int, help='number of threads (defaults to 16)', default=16)

    args = parser.parse_args(argv)

    # setup daemons ^._.^
    for _ in range(args.threads):
        worker = threading.Thread(
            target=testproxy,
            args=(
                args.url,
                args.timeout,
                proxylistq,
                lock,
                goodproxies,
                badproxies))
        worker.setDaemon(True)
        worker.start()

    start = time.time()

    # load a list of proxies from the proxy file
    with open(args.file) as proxyfile:
        for line in proxyfile:
            proxylistq.put(line.strip())

    # block main thread until the proxy list queue becomes empty
    proxylistq.join()

    # save results to file
    with open("result.txt", 'w') as resultfile:
        resultfile.write('\n'.join(goodproxies))

    # some metrics
    print("Runtime: {0:.2f}s".format(time.time() - start))


if __name__ == "__main__":
    main(sys.argv[1:])
