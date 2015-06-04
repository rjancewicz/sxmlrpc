
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

import os
import re
import ssl
import sys
import stat

REGEX_TYPE = type(re.compile(''))

thread_local = threading.local()

_xmlrpc_sessions = dict({})

PIDFILE = '/var/run/sxmlrpc.pid'

LOG_DIR = '/var/log/sxmlrpc'

DISPATCH_LOG = 'dispatch.log'
EVENT_LOG    = 'events.log'
FAULT_LOG    = 'faults.log'

LOG_FORMAT = "%(asctime)-15s %(message)s"

TLS_NONE   = 0
TLS_TRY    = 1
TLS_DEMAND = 2

class SecureXMLRPCRequestHandler(SimpleXMLRPCRequestHandler):

    XMLRPC_COOKIE = "XMLRPC_SESSION"

    def init_session(self):

        thread_local.thread_status = True

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

        """
        X-Forwarded-For
        """

        if self.headers.has_key('X-Forwarded-For'):
            thread_local.proxy_address = self.headers.getheader('X-Forwarded-For').split(',')[0].strip()
        else:
            thread_local.proxy_address = None

        (thread_local.client_address, _) = self.client_address

    def end_headers(self):
        self.wfile.write("{0}\r\n".format(self.cookie.output().strip()))
        SimpleXMLRPCRequestHandler.end_headers(self)

    def do_POST(self):
        self.init_session()
        SimpleXMLRPCRequestHandler.do_POST(self)



class SecureXMLRPCDispatcher(SimpleXMLRPCDispatcher):

    ALLOW = True
    DENY = False

    _access_control = dict({
        'STATIC': dict({}),
        'DYNAMIC': dict({})
        })
    
    default_access = ALLOW
    needs_username = set()
    needs_context = set()

    log_faults = True

    _auth_function = None
    _users = dict()

    _trusted_proxies = set()

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
                thread_local.username = username
                self.log_event("Login Correct")
                return True
            else:
                self.log_event("Login Incorrect")
        # by default we fail authentication 
        return False

    def auth_whoami(self, username): 
        return username

    def auth_setuid(self, username):

        xmlrpc_session = getattr(thread_local, 'xmlrpc_session', None)

        if xmlrpc_session:
            # we opt to immediately expire the session if the setuid is called from a non-existant session
            #  the user may have gotten around '_evaluate_acls' but we can at least block here
            (prior, expire) = _xmlrpc_sessions.get(xmlrpc_session, ('_', datetime.now()))
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

    def register_trusted_proxy(self, proxy):

        if isinstance(proxy, types.StringTypes):
            self._trusted_proxies.add(proxy)
        elif hasattr(proxy, '__iter__'):
            self._trusted_proxies.update(set(proxy))
        else:
            raise TypeError("")


    def _setup_session(self):

        thread_local.username = 'anonymous'

        xmlrpc_session = getattr(thread_local, 'xmlrpc_session', None)

        if xmlrpc_session:
            (username, expire) = _xmlrpc_sessions.get(xmlrpc_session, ('anonymous', None))
            
            if xmlrpc_session in _xmlrpc_sessions: 
                if expire:
                    if expire > datetime.now():
                        thread_local.username = username
                    else:
                        del _xmlrpc_sessions[xmlrpc_session]
            else:
                _xmlrpc_sessions[xmlrpc_session] = (username, expire)


    # override if needed 
    def evaluate_access(self, method, username):

        if method not in self.funcs.keys():
            return self.ALLOW

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

    def include_context(self, methods):

        if isinstance(methods, REGEX_TYPE):

            for method in self.funcs.keys():
                if methods.match(method):
                    self.needs_context.add(method)

        elif isinstance(methods, types.StringTypes):
            self.needs_context.add(methods)
        elif hasattr(methods, '__iter__'):
            self.needs_context.update(set(methods))
        else:
            raise TypeError("")

    '''
    def log_event(self, message=None, level=logging.INFO):

        """
            log format

            ISO8601 client=client_address[/proxy_address]* method=<method> user=<username> MESSAGE

        """

        if message is None:
            message = str()

        method         = getattr(thread_local, 'method', 'NULL')
        username       = getattr(thread_local, 'username', 'anonymous')
        client_address = getattr(thread_local, 'client_address', "0.0.0.0")
        proxy_address  = getattr(thread_local, 'proxy_address', None)

        if not omit_prefix:
            prefix = "method=\"{method}\" user=\"{username}\" "
            message = prefix + message

        forwarded_for = ""

        if proxy_address is not None and client_address in self._trusted_proxies:
            forwarded_for = "forwarded_for=" + proxy_address

        body = message.format(username=username, method=method)
        body = "client={client_address} {forwarded} {body}".format(client_address=client_address, forwarded=forwarded_for, body=body)

        self.logger.log(level, body)
    '''

    def _log_dispatch(self, method):

        prefix = self._log_prefix()

        message = ""

        if method not in self.funcs:
            message = "- requested method is not supported."

        body = "{prefix} {message}".format(
            prefix = prefix,
            message = message)

        self._dispatch_logger.info(body)

    def _log_fault(self, fault):

        if isinstance(fault, Exception) or isinstance(fault, Fault):

            prefix = self._log_prefix()

            message = repr(fault)

            body = "{prefix} {message}".format(
                prefix = prefix,
                message = message)

            self._fault_logger.error(body)

        else:

            pass # todo - log the fact that we tried to log a non-fault


    def _dispatch(self, method, params):

        self._setup_session()

        # when logging if method is None we will assume that we are logging from within the method
        thread_local.method = method

        self._log_dispatch(method)

        # this will raise a fault if auth is not permitted
        try:
            if not self.evaluate_access(method, thread_local.username):
                self.log_event("ACL Access Denied")
                raise xmlrpclib.Fault(401, "Unauthorized")

            if method in self.needs_username:
                params = (thread_local.username,) + params

            if method in self.needs_context:
                params = (self,) + params

            # by default we simply dispatch the method
            return SimpleXMLRPCDispatcher._dispatch(self, method, params)
        except Exception as fault:

            if self.log_faults: 
                self._log_fault(fault)

            raise fault



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

    def configure_logging(self, level=logging.DEBUG):

        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR)

        dispatch_path = "{0}/{1}".format(LOG_DIR, DISPATCH_LOG)
        fault_path    = "{0}/{1}".format(LOG_DIR, FAULT_LOG)
        event_path    = "{0}/{1}".format(LOG_DIR, EVENT_LOG)

        formatter = logging.Formatter(LOG_FORMAT)

        self._dispatch_logger = logging.getLogger('sxmlrpc-dispatch')
        self._fault_logger    = logging.getLogger('sxmlrpc-faults')
        self._event_logger    = logging.getLogger('sxmlrpc')

        # todo replace with auto-rotate handler 
        dispatch_handler = logging.FileHandler(dispatch_path)
        fault_handler    = logging.FileHandler(fault_path)
        event_handler    = logging.FileHandler(event_path)

        dispatch_handler.setFormatter(formatter)
        fault_handler.setFormatter(formatter)
        event_handler.setFormatter(formatter)

        self._dispatch_logger.addHandler(dispatch_handler)
        self._fault_logger.addHandler(fault_handler)
        self._event_logger.addHandler(event_handler)

        self._dispatch_logger.setLevel(level)
        self._fault_logger.setLevel(level)
        self._event_logger.setLevel(level)

        #global sxmlrpc_logger
        #sxmlrpc_log_event = self.log_event

    def _log_prefix(self):

        method         = getattr(thread_local, 'method', 'NULL')
        username       = getattr(thread_local, 'username', 'anonymous')
        client_address = getattr(thread_local, 'client_address', "0.0.0.0")
        proxy_address  = getattr(thread_local, 'proxy_address', None)
        forwarded_for  = ""

        if proxy_address is not None and client_address in self._trusted_proxies:
            forwarded_for = " forwarded_for=" + proxy_address

        prefix = "client_address={client}{forward} method=\"{method}\" user=\"{username}\"".format(
            client = client_address,
            forward = forwarded_for,
            method = method,
            username = username
            )

        return prefix

    def log_event(self, message, level=logging.INFO):

        prefix = "<<SXMLRPC SERVER>>"

        thread_status = getattr(thread_local, 'thread_status', False)

        if thread_status:
            prefix = self._log_prefix()

        body = "{prefix} {message}".format(prefix=prefix, message=message)

        self._event_logger.log(level, body)


    def __init__(self, addr, request_handler=SecureXMLRPCRequestHandler,
                 logRequests=True, allow_none=True, encoding=None, bind_and_activate=True,
                 tls=TLS_TRY, crtfile="./certificate.crt", keyfile="./certificate.key"):
        self.logRequests = logRequests

        SimpleXMLRPCDispatcher.__init__(self, allow_none, encoding)
        SocketServer.TCPServer.__init__(self, addr, request_handler, False)

        if fcntl is not None and hasattr(fcntl, 'FD_CLOEXEC'):
            flags = fcntl.fcntl(self.fileno(), fcntl.F_GETFD)
            flags |= fcntl.FD_CLOEXEC
            fcntl.fcntl(self.fileno(), fcntl.F_SETFD, flags)


        if tls != TLS_NONE:

            try:
                cstat = stat.S_ISREG(os.stat(crtfile).st_mode)
                kstat = stat.S_ISREG(os.stat(keyfile).st_mode)
                if cstat and kstat:
                    self.socket = ssl.wrap_socket(self.socket, keyfile=keyfile, certfile=crtfile)
                else:
                    raise OSError
            except OSError: 
                if tls == TLS_DEMAND:
                    sys.stderr.write(">>> SSL Error: [Fatal] TLS_DEMAND is specified however the Certificate or Key could not be found.\n")
                    sys.stderr.write(">>>     crtfile = {0}\n".format(crtfile))
                    sys.stderr.write(">>>     keyfile = {0}\n".format(keyfile))
                    sys.exit(-1)
                else:
                    sys.stderr.write(">>> SSL Error: Certificate or Key could not be found, starting unencrypted XMLRPC service.\n")


        self.configure_logging()

        self.server_address = addr

        if bind_and_activate:
            self.server_bind()
            self.server_activate()


    def daemonize(self):
        
        try:
            import daemon

            daemon.daemonize(PIDFILE)
            self.log_event("Starting Secure XMLRPC Server [background]: https://{0}:{1}/".format(self.server_address[0], self.server_address[1]))
            SocketServer.TCPServer.serve_forever(self)

        except ImportError:
            sys.stderr.write("Unable to daemonize failing back to foreground.\n")
            self.serve_forever(daemon=False)


    def serve_forever(self, daemon=False):

        if daemon:
            self.daemonize()
        
        else:
            try:
                self.log_event("Starting Secure XMLRPC Server [foreground]: https://{0}:{1}/".format(self.server_address[0], self.server_address[1]))
                SocketServer.TCPServer.serve_forever(self)
            except KeyboardInterrupt: 
                sys.stderr.write("Caught ctl-c signal gracefully exiting ... \n")
            finally:
                SocketServer.TCPServer.server_close(self)


def log_example():

    server.log_event("Sample Event Log")


if __name__ == "__main__":

    global server

    server = SecureXMLRPCServer( ("127.0.0.1", 1337) )

    server.register_auth_functions()

    server.register_function(lambda x: x, "echo")
    server.register_function(log_example, "log_example")

    server.register_user('russell', 'secret')

    server.access_allow('auth.setuid', ['russell'])
    server.access_allow_everyone('log_example')

    server.log_event("Example System Log")

    server.register_function(lambda x: x, "unknown")

    server.serve_forever(daemon=False)

