import xmlrpclib
from xmlrpclib import Fault

import Cookie

"""
    TODO: ssl connection
"""

class SecureXMLRPCTransport(xmlrpclib.SafeTransport):

    xmlrpc_cookie = None

    def single_request(self, host, handler, request_body, verbose=0):
        # issue XML-RPC request

        h = self.make_connection(host)
        if verbose:
            h.set_debuglevel(1)

        try:
            self.send_request(h, handler, request_body)
            self.send_host(h, host)
            self.send_user_agent(h)
            self.send_cookie(h)
            self.send_content(h, request_body)

            response = h.getresponse(buffering=True)
            if response.status == 200:
                self.verbose = verbose
                return self.parse_response(response)
        except Fault:
            raise
        except Exception:
            # All unexpected errors leave connection in
            # a strange state, so we clear it.
            self.close()
            raise

        #discard any response data and raise exception
        if (response.getheader("content-length", 0)):
            response.read()
        raise ProtocolError(
            host + handler,
            response.status, response.reason,
            response.msg,
            )

    def parse_response(self, response):

        if hasattr(response,'getheader'):
            cookie_str = response.getheader("Set-Cookie", None)
            if cookie_str:
                cookie = Cookie.SimpleCookie(cookie_str)
                if cookie.has_key("XMLRPC_SESSION"):
                    self.xmlrpc_cookie = cookie["XMLRPC_SESSION"].value

        return xmlrpclib.Transport.parse_response(self, response)

    def send_cookie(self, connection):
        if self.xmlrpc_cookie:
            connection.putheader("Cookie", "XMLRPC_SESSION=" + self.xmlrpc_cookie)

class SecureXMLRPCClient(xmlrpclib.ServerProxy):

    def __init__(self, uri, transport=None, encoding=None, verbose=0, allow_none=0, use_datetime=0):

        transport = SecureXMLRPCTransport(use_datetime = use_datetime)

        xmlrpclib.ServerProxy.__init__(self, uri, transport, encoding, verbose, allow_none, use_datetime)

if __name__ == "__main__":

    proxy = SecureXMLRPCClient('http://localhost:1338')

    print proxy.auth.whoami()

    print proxy.auth.login('russell','secret')

    print proxy.auth.whoami()


    print proxy.auth.setuid('steve')

    print proxy.auth.whoami()

    #print proxy.secret_echo('Hello, Fault')






