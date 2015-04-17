
# used to generate cookies 

from SimpleXMLRPCServer import *
import SocketServer

from uuid import uuid4
import Cookie

import threading

from datetime import datetime, timedelta
import types

import logging

import hashlib

import re
import ssl
import sys

REGEX_TYPE = type(re.compile(''))

thread_local = threading.local()

_xmlrpc_sessions = dict({})


LOG_PATH = '/var/log/xmlrpc/xmlrpc.log'
LOG_FORMAT = "%(asctime)-15s %(message)s"
PIDFILE = '/var/run/sxmlrpc.pid'

class SecureXMLRPCRequestHandler(SimpleXMLRPCRequestHandler):

    XMLRPC_COOKIE = "XMLRPC_SESSION"

    def init_session(self):

        xmlrpc_session = None 

        if self.headers.has_key('cookie'):
            self.cookie = Cookie.SimpleCookie(self.headers.getheader('cookie'))
            
            if self.cookie.has_key(self.XMLRPC_COOKIE):
                xmlrpc_session = self.cookie[self.XMLRPC_COOKIE].value

        # generate a new session identifier
        if xmlrpc_session is None:
            xmlrpc_session = str.upper(hex(int(uuid4()))[2:-1])

        self.cookie = Cookie.SimpleCookie()
        self.cookie[self.XMLRPC_COOKIE] = xmlrpc_session
        # TODO expires hours=8 

        thread_local.xmlrpc_session = xmlrpc_session

    def do_POST(self):
        """Handles the HTTP POST request.

        Attempts to interpret all HTTP POST requests as XML-RPC calls,
        which are forwarded to the server's _dispatch method for handling.
        """

        self.init_session()

        # Check that the path is legal
        if not self.is_rpc_path_valid():
            self.report_404()
            return

        try:
            # Get arguments by reading body of request.
            # We read this in chunks to avoid straining
            # socket.read(); around the 10 or 15Mb mark, some platforms
            # begin to have problems (bug #792570).
            max_chunk_size = 10*1024*1024
            size_remaining = int(self.headers["content-length"])
            L = []
            while size_remaining:
                chunk_size = min(size_remaining, max_chunk_size)
                chunk = self.rfile.read(chunk_size)
                if not chunk:
                    break
                L.append(chunk)
                size_remaining -= len(L[-1])
            data = ''.join(L)

            data = self.decode_request_content(data)
            if data is None:
                return #response has been sent

            # In previous versions of SimpleXMLRPCServer, _dispatch
            # could be overridden in this class, instead of in
            # SimpleXMLRPCDispatcher. To maintain backwards compatibility,
            # check to see if a subclass implements _dispatch and dispatch
            # using that method if present.
            response = self.server._marshaled_dispatch(
                    data, getattr(self, '_dispatch', None), self.path
                )
        except Exception, e: # This should only happen if the module is buggy
            # internal error, report as HTTP server error
            self.send_response(500)

            # Send information about the exception if requested
            if hasattr(self.server, '_send_traceback_header') and \
                    self.server._send_traceback_header:
                self.send_header("X-exception", str(e))
                self.send_header("X-traceback", traceback.format_exc())

            self.send_header("Content-length", "0")
            self.end_headers()
        else:
            # got a valid XML RPC response
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            if self.encode_threshold is not None:
                if len(response) > self.encode_threshold:
                    q = self.accept_encodings().get("gzip", 0)
                    if q:
                        try:
                            response = xmlrpclib.gzip_encode(response)
                            self.send_header("Content-Encoding", "gzip")
                        except NotImplementedError:
                            pass
            self.send_header("Content-length", str(len(response)))
            self.wfile.write(self.cookie)
            self.end_headers()
            self.wfile.write(response)


class SecureXMLRPCDispatcher(SimpleXMLRPCDispatcher):

    ALLOW = True
    DENY = False

    _access_control = dict({
        'STATIC': dict({}),
        'DYNAMIC': dict({})
        })
    
    default_access = ALLOW
    needs_username = set()

    _auth_function = None
    _users = dict()


    # override if needed
    def register_user(self, username, password):
        passwd_hash = hashlib.sha1(password).hexdigest()
        self._users[username] = passwd_hash

    def _basic_auth(self, username, password):
        passwd_hash = hashlib.sha1(password).hexdigest()
        return self._users.get(username, unicode()) == passwd_hash

    # -- used to set the internal auth function 
    def register_auth_proxy(self, function):
        self._auth_function = function

    def auth_login(self, username, password):

        xmlrpc_session = getattr(thread_local, 'xmlrpc_session', None)

        if xmlrpc_session:

            # ... do real authenticaiton ... 
            if self._auth_function(username, password):
                expire = datetime.now() + timedelta(hours=8)
                _xmlrpc_sessions[xmlrpc_session] = (username, expire)
                self.logger.warning("[auth.login] {0} login success".format(username))
                return True
            else:
                self.logger.warning("[auth.login] {0} login incorrect".format(username))

        # by default we fail authentication 
        return False

    def auth_whoami(self, username): 
        return username

    def auth_setuid(self, username):

        xmlrpc_session = getattr(thread_local, 'xmlrpc_session', None)

        if xmlrpc_session:
            # we opt to immediately expire the session if the setuid is called from a non-existant session
            #  the user may have gotten around '_evaluate_acls' but we can at least block here
            (_, expire) = _xmlrpc_sessions.get(xmlrpc_session, ('_', datetime.now()))
            _xmlrpc_sessions[xmlrpc_session] = (username, expire)
            self._setup_session()
            return True

        return False

    def register_auth_functions(self):

        self.funcs.update({
            'auth.login'  : self.auth_login,
            'auth.setuid' : self.auth_setuid,
            'auth.whoami' : self.auth_whoami
            })

        if self._auth_function is None:
            self._auth_function = self._basic_auth

        # once auth is invoked we flip our default access
        self.default_access = self.DENY

        self.include_username('auth.whoami')

        self.access_allow_everyone('auth.login')
        self.access_allow_everyone('auth.whoami')


    def _setup_session(self):

        thread_local.username = 'anonymous'

        xmlrpc_session = getattr(thread_local, 'xmlrpc_session', None)

        if xmlrpc_session:
            (username, expire) = _xmlrpc_sessions.get(xmlrpc_session, ('anonymous', None))

            if expire:
                if expire > datetime.now():
                    thread_local.username = username
                else:
                    del _xmlrpc_sessions[xmlrpc_session]


    # override if needed 
    def evaluate_access(self, method, username):

        access = self.default_access

        # apply static and dynamic rules 

        static = self._access_control['STATIC']
        dynamic = self._access_control['DYNAMIC']

        if method in dynamic:

            (allow, deny) = dynamic[method]

            if self.default_access is self.ALLOW:
                for expression in deny:
                    if expression.match(username):
                        access = self.DENY
                for expression in allow:
                    if expression.match(username):
                        access = self.ALLOW
            else:
                for expression in allow:
                    if expression.match(username):
                        access = self.ALLOW
                for expression in deny:
                    if expression.match(username):
                        access = self.DENY

        if method in static:

            (allow, deny) = static[method]

            if self.default_access is self.ALLOW:
                if username in deny:
                    access = self.DENY
                if username in allow:
                    access = self.ALLOW
            else:
                if username in allow:
                    access = self.ALLOW
                if username in deny:
                    access = self.DENY

        return access


    def access_allow_everyone(self, method):
        self._access_update(method, re.compile(r'.*'), self.ALLOW)
        
    def access_deny_everyone(self, method):
        self._access_update(method, re.compile(r'.*'), self.DENY)

    def access_allow_authenticated(self, method):
        self._access_update(method, re.compile(r'(^anonymous)'), self.ALLOW)
        
    def access_deny_authenticated(self, method):
        self._access_update(method, re.compile(r'(^anonymous)'), self.DENY)



    def access_allow(self, methods, usernames): 
        self._access_update(methods, usernames, self.ALLOW)

    def access_deny(self, methods, usernames):
        self._access_update(methods, usernames, self.DENY)

    def _access_update_static(self, method, usernames, access):

        static = self._access_control['STATIC']

        if method in static:
            (allow, deny) = static[method]
        else:
            (allow, deny) = (set(), set())

        if isinstance(usernames, types.StringTypes):

            if access is self.ALLOW:
                allow.add(usernames)
            else:
                deny.add(usernames)

        elif hasattr(usernames, '__iter__'):

            if access is self.ALLOW:
                allow.update(set(usernames))
            else:
                deny.update(set(usernames))

        else:
            raise TypeError('username specifier type must be a string or iterable.')

        self._access_control['STATIC'][method] = (allow, deny)

    def _access_update_dynamic(self, method, expression, access):
        
        dynamic = self._access_control['DYNAMIC']

        if method in dynamic:
            (allow, deny) = dynamic[method]
        else:
            (allow, deny) = (set(), set())

        if access is self.ALLOW:
            allow.add(expression)
        else:
            deny.add(expression)

        self._access_control['DYNAMIC'][method] = (allow, deny)

    def _access_update(self, methods, usernames, access):


        if isinstance(methods, types.StringTypes):
            
            if isinstance(usernames, REGEX_TYPE):
                self._access_update_dynamic(methods, usernames, access)
            else:
                self._access_update_static(methods, usernames, access)

        elif isinstance(methods, REGEX_TYPE):

            for method in self.funcs.keys():
                if methods.match(method):
                    self._access_update(method, usernames, access)
  
        elif hasattr(methods, '__iter__'):

            for method in methods:
                self._access_update(method, usernames, access)

        else:
            raise TypeError('method specifier type must be string, regex, or iterable.')


    def include_username(self, methods):

        if isinstance(methods, REGEX_TYPE):

            for method in self.funcs.keys():
                if methods.match(method):
                    self.needs_username.add(method)

        elif isinstance(methods, types.StringTypes):
            self.needs_username.add(methods)
        elif hasattr(methods, '__iter__'):
            self.needs_username.update(set(methods))
        else:
            raise TypeError("")

    def log_request(self, method):

        if method not in self.funcs:
            self.logger.warning("[{0}] {1} - method not found.".format(method, thread_local.username))
        else:
            self.logger.warning("[{0}] {1}".format(method, thread_local.username))



    def _dispatch(self, method, params):

        self._setup_session()

        self.log_request(method)

        # this will raise a fault if auth is not permitted
        if not self.evaluate_access(method, thread_local.username):
            raise xmlrpclib.Fault(401, "Unauthorized")

        if method in self.needs_username:
            params = (thread_local.username,) + params

        # by default we simply dispatch the method
        return SimpleXMLRPCDispatcher._dispatch(self, method, params)


"""
    TODO: tls (auto generate certificates if not provided, encryption is not an option )
"""

class SecureXMLRPCServer(SocketServer.TCPServer, SecureXMLRPCDispatcher):
    """
    """

    ALLOW = True
    DENY = False


    allow_reuse_address = True
    _send_traceback_header = False

    def __init__(self, addr, request_handler=SecureXMLRPCRequestHandler,
                 logRequests=True, allow_none=True, encoding=None, bind_and_activate=True,
                 crtfile="./certificate.crt", keyfile="./certificate.key"):
        self.logRequests = logRequests

        SimpleXMLRPCDispatcher.__init__(self, allow_none, encoding)
        SocketServer.TCPServer.__init__(self, addr, request_handler, False)

        if fcntl is not None and hasattr(fcntl, 'FD_CLOEXEC'):
            flags = fcntl.fcntl(self.fileno(), fcntl.F_GETFD)
            flags |= fcntl.FD_CLOEXEC
            fcntl.fcntl(self.fileno(), fcntl.F_SETFD, flags)


        logging.basicConfig(format=LOG_FORMAT, filename=LOG_PATH)

        self.logger = logging.getLogger('xmlrpc')

        # todo certificates

        self.logger.setLevel(logging.DEBUG)

        self.socket = ssl.wrap_socket(self.socket, keyfile=keyfile, certfile=crtfile)

        self.logger.info("starting secure xmlrpc server: https://{0}:{1}/".format(addr[0], addr[1]))

        if bind_and_activate:
            self.server_bind()
            self.server_activate()



    def daemonize(self):
        
        try:
            import daemon

            daemon.daemonize(PIDFILE)
                SocketServer.TCPServer.serve_forever(self)

        except ImportError:
            sys.stderr.write("Unable to daemonize failing back to foreground.\n")
            self.serve_forever(daemon=False)

        

    def serve_forever(self, daemon=False):

        if daemon:
            self.daemonize()
        
        else:
            try:
                SocketServer.TCPServer.serve_forever(self)
            except KeyboardInterrupt: 
                sys.stderr.write("Caught ctl-c signal exiting ... \n")
            finally:
                SocketServer.TCPServer.server_close(self)




if __name__ == "__main__":

    server = SecureXMLRPCServer( ("127.0.0.1", 1337) )

    server.register_auth_functions()

    server.register_function(lambda x: x, "echo")

    server.register_user('russell', 'secret')

    server.access_allow('auth.setuid', ['russell'])


    server.serve_forever(daemon=True)

