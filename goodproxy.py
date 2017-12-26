""" A multithreaded proxy checker with anonymity analysis

Given a file containing a list of proxies, in a form of ip:port, attempts
to connect through each proxy to a local web server. If successful, the web
server collects the headers coming out of the proxy and return them to the
calling thread for anonymity analysis.

Anonymity levels are defined as follows:

    Level 1: Elite Proxy - hides source IP and that it is a proxy
    Level 2: Anonymous Proxy - hides source IP but labels itself as a proxy
    Level 3: Transparent Proxy - both source IP and proxy details are visible

Because this program spins off a local web server to simulate a recipient of
proxied requests - the port it runs on needs to be port-forwarded on
your router.

Usage:

    goodproxy.py [-h] -wanip WANIP [-port PORT] [-file FILE]
                [-timeout TIMEOUT] [-threads THREADS]

Parameters:

    -wanip   -- your external IP (as at whatismyip.org)
    -port    -- for the local web server (default 80)
    -file    -- filename with a list of proxies per line (default proxies.txt)
    -timeout -- time in seconds for connecting to a proxy (default 1.0)
    -threads -- number of threads to boost performance (default 8)

Functions:

    test_proxy           -- does the actual connecting through a proxy
    main                 -- creates daemon threads, writes results to a file

Output:

    Creates a result.csv with a comma-delimited list of proxies and
    results like the anonymity level, time to connect and headers sent out by
    the proxy.
"""
import argparse
import http.client
import json
import logging
import queue
import socket
import sys
import threading
import time
import urllib.request

import simpleserver

""" Utility Functions """


def loadproxylist(args, proxy_list):
    """ load a list of proxies from the proxy file """
    with open(args.file) as proxyfile:
        for line in proxyfile:
            proxy_list.put(line.strip())


def saveresults(good_proxies):
    """ save results to file """
    with open("result.csv", 'w') as result_file:
        result_file.write('PROXY,LEVEL,TIME,HEADERS\n')
        result_file.write('\n'.join(good_proxies))


def processinputparams(argv):
    """ Process input parameters """
    parser = argparse.ArgumentParser(
        description='A multithreaded proxy checker and anonymity analyzer.')
    parser.add_argument(
        '-wanip', help='your external IP (whatismyip.org)', required=True)
    parser.add_argument(
        '-port', help='port for the local web server (default 80)',
        default=80, type=int)
    parser.add_argument(
        '-file', help='a file with a list of proxies (default proxies.txt)',
        default="proxies.txt")
    parser.add_argument(
        '-timeout',
        type=float, help='timeout in seconds (default 1.0)', default=1.0)
    parser.add_argument(
        '-threads', type=int, help='number of threads (default 8)',
        default=8)

    return parser.parse_args(argv)


def configureurlrequest(proxytotest, wanip, port):
    """configure urllib.request with a proxy
    :rtype: urllib.request.Request
    """

    proxy = urllib.request.ProxyHandler({'http': proxytotest})
    opener = urllib.request.build_opener(proxy)
    urllib.request.install_opener(opener)

    # some sites block frequent querying from programmatic methods so
    # set a header to simulate a browser
    return urllib.request.Request(
        "http://{0}:{1}".format(wanip, port),
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64)' +
                               'AppleWebKit/537.36 (KHTML, like Gecko)' +
                               'Chrome/43.0.2357.134 Safari/537.36'})


def getresponse(request, url_timeout):

    try:

        return urllib.request.urlopen(
            request,
            timeout=float(url_timeout)).read().decode("utf-8")

    except urllib.request.URLError:
        pass
        # if isinstance(err.reason,socket.timeout):
        #    print("Error: Timeout")
        # else:
        #    print("Error: " + err.reason)

    except (urllib.request.HTTPError,
            socket.error, http.client.HTTPException):

        # ignore the usual errors related to bad proxies like connectivity
        # timeouts, refused connections, HTTPError, URLError, etc
        # print("Error" + urllib.request.URLError + urllib.request.HTTPError + socket.error, http.client.HTTPException )
        pass


def analyzeheaders(headers_json, wanip, port):

    # parse out the keys and values for easier comparison
    header_keys = set([item[0].upper() for item in headers_json])
    header_values = [item[1].upper() for item in headers_json]

    # sanity check: if num of header keys doesn't equal to num of header
    # values then something was wrong with the JSON or the headers so
    # skip the proxy
    if len(header_keys) != len(header_values):
        return None

    # analyze headers to decide which level of anonymity this proxy
    # exhibits. Transparent proxies show the source IP and may contain
    # the X-Forwarded-For header. Anonymous proxies don't send out the
    # source IP by advertize themselves as being proxies. Anything else
    # can be classified as an Elite proxy that shows neither the info
    # about the source or that it is a proxy.
    if wanip + ":" + str(port) in header_values:
        proxy_type = "Transparent"
    elif bool([key for key in header_keys if "FORWARD" in key.upper()
                                             or "VIA" in key.upper()
                                             or "PROXY" in key.upper()]):
        proxy_type = "Anonymous"
    else:
        proxy_type = "Elite"

    return proxy_type


def test_proxy(
        url_timeout, allproxies, good_proxies, wanip, port):
    """ Attempt to connect through a proxy.

    This function is used in a daemon thread and will loop continuously while
    waiting for available proxies in the proxy_list. Once proxy_list contains
    a proxy, this function will extract it and the proxy_list queue will
    automatically lock until the thread is done. A connection to the local web
    server will then be attempted through the proxy, using a URL consisting of
    wanip:port. Results from successfull connections will be saved into the
    good_proxies list. Exceptions, like connect failures, are ignored
    since we are interested in working proxies only.

    """

    while True:

        # .get() locks the Queue to be thread safe and blocks until an item is available
        proxytotest = allproxies.get()

        start = time.time()

        request = configureurlrequest(proxytotest, wanip, port)
        response = getresponse(request, url_timeout)

        # format JSON response to get all headers from the proxy
        try:

            headers_json = json.loads(response)

        except (TypeError, json.JSONDecodeError):
            continue

        proxy_type = analyzeheaders(headers_json, wanip, port)

        print(
            "{0: <21} {1: <12} {2:>5.1f}s  {3}".format(proxytotest,
                                                       proxy_type,
                                                       time.time() -
                                                       start,
                                                       headers_json))

        # save the proxy and analysis results to a list
        # threading.Lock() is used to prevent multiple threads from
        # corrupting this list as its a shared resource
        # with lock:

        good_proxies.append(
            "{0},{1},{2:.1f},{3}".format(
                proxytotest,
                proxy_type,
                time.time() -
                start,
                headers_json))

        # release the queue containing a list of proxies to test
        # this prevents multiple threads from re-testing same proxies
        allproxies.task_done()


def main(argv):
    """ Main Function

    Loads proxies from a file and spins of a simple web server in a sub-thread.
    Then creates a number of daemon threads which monitor a queue for available
    proxies to test. Once completed, successful results are written out to a
    results.csv file.

    """

    proxy_list = queue.Queue()  # Hold a list of proxy ip:ports
    # lock = threading.Lock()  # locks good_proxies list
    good_proxies = []  # proxies that passed connectivity tests

    # configure logging
    logging.basicConfig(filename="tester.log", level=logging.DEBUG)

    # parse input parameters
    args = processinputparams(argv)

    # load in a list of proxies from a text file
    loadproxylist(args, proxy_list)

    # start local web server
    simpleserver.start(args.port)

    # setup daemons ^._.^
    for _ in range(args.threads):
        worker = threading.Thread(
            target=test_proxy,
            args=(
                args.timeout,
                proxy_list,
                good_proxies,
                args.wanip,
                args.port))
        worker.setDaemon(True)
        worker.start()

    start = time.time()

    try:
        # block main thread until the proxy list queue becomes empty
        proxy_list.join()

    except KeyboardInterrupt:
        print("Finished")

    saveresults(good_proxies)

    # some metrics
    print("Finished in {0:.1f}s".format(time.time() - start))


if __name__ == "__main__":
    main(sys.argv[1:])
