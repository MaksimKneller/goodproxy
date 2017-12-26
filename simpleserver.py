""" A simple multithreaded web server

This web server is based on http.server.HTTPServer and enabled multithreading
via the ThreadingMixIn. This server's only purose is to intercept incoming
headers and send them back in JSON format.

"""
from socketserver import ThreadingMixIn
import http.server
import json
import logging
import socket
import threading


class ThreadedHTTPServer(ThreadingMixIn, http.server.HTTPServer):

    """ Enable multithreading in a simple HTTP server """
    pass


class MyHandler(http.server.BaseHTTPRequestHandler):

    """ Handle the incoming HTTP request """

    def do_GET(self):
        """ Process the GET portion of the HTTP request """


        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

        # create a JSON object out of the incoming headers and send them
        # to the requestor
        try:
            hdrsjson = json.JSONEncoder().encode(sorted(self.headers.items()))
            self.wfile.write(bytes(hdrsjson, "utf-8"))


        except:
            logging.DEBUG(
                "Server JSON encoding error for {0}:{1} - {2}".format(
                    self.client_address[0], self.client_address[1],
                    self.headers.items()))

        self.wfile.write(bytes("\n", "utf-8"))

        return

    def log_message(self, format, *args):
        """ Suppress logging of connection events """

        return


def start(port):
    """ Start the web server

    Aside from the web server being multithreaded, the server itself is started
    in a thread. This effectively puts the web server into the background while
    allowing the rest of the main thread to continue processing.

    """

    # configure logging
    logging.basicConfig(filename="server.log", level=logging.DEBUG)

    # the local web server MUST use the LAN IP of this host; not 'localhost'
    # or '127.0.0.1'. Because port-forwarding uses this hostname - the web
    # server must use it as well so that external proxies can connect to it
    # successfully through the router
    host = socket.gethostbyname(socket.gethostname())

    print("Starting server on: {0}:{1}".format(host, port))

    server = ThreadedHTTPServer((host, port), MyHandler)

    # this spins off the web server in a separate thread
    # marking the thread a daemon will cause it to shut down automatically
    # once the main thread ends
    threading.Thread(target=server.serve_forever, daemon=True).start()

    return

if __name__ == "__main__":

    start(8081)

    while True:
        pass
