<?php
/*
    Russell J. Jancewicz - 2015-05-19
    
    MIT License

    Copyright (c) 2015 Russell Jancewicz

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/


define("XMLRPC_COOKIE", "XMLRPC_SESSION");

class SXMLRPCSystemError extends Exception {}
class SXMLRPCFault extends Exception {}

class SecureXMLRPCClient {

    private $xmlrpc_cookie = null;
    private $x_forwarded_for = null;
    private $_url = null;
    private $_port = null;
    private $_tls = 2;

    public function __construct($url="https://127.0.0.1/", $port=1337, $proxy=false, $tls=2) {
        
        session_start();

        $this->_url = $url;
        $this->_port = $port;
        $this->_proxy = $proxy;
        $this->_tls = $tls;

        if ($proxy && array_key_exists(XMLRPC_COOKIE, $_SESSION)) {
            $this->x_forwarded_for = $this->_get_client_addr();
            $this->xmlrpc_cookie = $_SESSION[XMLRPC_COOKIE];
        }
    }


    private function _get_client_addr()  {

        $addr = $_SERVER['REMOTE_ADDR'];

        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $addr = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $addr = $_SERVER['HTTP_X_FORWARDED_FOR'];
        }

        return $addr;
    }


    private function _parse_headers($text) {

        $headers = array();

        foreach (explode("\r\n", $text) as $index => $line) {
            if ($index === 0) {
                $headers["HTTP"] = array($line);
            } else {

                if (stripos($line, ": ") !== false) {
                    list($key, $value) = explode(': ', $line, 2);

                    if (array_key_exists($key, $headers)) {
                        $headers[$key][] = $value;
                    } else {
                        $headers[$key] = array($value);
                    }
                }
            }
        }

        return $headers;
    }

    // https://tools.ietf.org/html/rfc6265#section-5.2
    static private function _parse_cookie($cookie) {

        static $COOKIE_AV_PAIRS = array("Expires", "Domain", "Path");
        static $COOKIE_AV_SINGLES = array("Secure", "HttpOnly");

        $cookies = array();
        $cookies["VALUES"] = array();

        $morsels = explode(";", $cookie);

        foreach ($morsels as $j => $morsel) {

            $morsel = trim($morsel);

            if (in_array($morsel, $COOKIE_AV_SINGLES)) {
                // skip for now
            } else {

                if (stripos($morsel, "=") !== false) {

                    list($key, $pair) = explode("=", $morsel, 2); 

                    if (in_array($key, $COOKIE_AV_PAIRS)) {
                        // TODO
                    } else {
                        $cookies["VALUES"][$key] = $pair;
                    }
                }
            }
        }

        return $cookies;
    }

    private function _init_session($headers) {

        // scan all headers for Set-Cookie headers
        if (array_key_exists("Set-Cookie", $headers)) {
            foreach ($headers["Set-Cookie"] as $i => $str_cookie) {

                // Parse cookies accoring to RFC
                $cookie = SecureXMLRPCClient::_parse_cookie($str_cookie);

                $values = $cookie["VALUES"];

                // Search for the XMLRPC_SESSION id 
                foreach ($values as $key => $pair) {
                    if (strcasecmp($key, XMLRPC_COOKIE) === 0) {
                        // if found set and stop looking
                        $this->xmlrpc_cookie = $pair;
                        break;
                    }
                }
            }
        }

        // If we are acting as a proxy for an extrenally authenticated client
        //  i.e. a web-browser; we pass the cookie up and allow passthorugh 
        if ($this->_proxy) {
            $_SESSION[XMLRPC_COOKIE] = $this->xmlrpc_cookie;
            #setcookie(XMLRPC_COOKIE, $this->xmlrpc_cookie);
        }

    }

    // handle the pure response from the curl client
    private function _parse_response($payload, $ch) {

        // split the headers and the body
        $hsize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);

        $str_headers = substr($payload, 0, $hsize);
        $body = substr($payload, $hsize);

        // parse headers 
        $headers = $this->_parse_headers($str_headers);

        // use headers to get session values
        $this->_init_session($headers);

        // return the decoded result 
        return xmlrpc_decode($body);
    }

    private function _raise_fault($fault) {
        if (xmlrpc_is_fault($fault)) {
            throw new SXMLRPCFault($fault["faultString"], $fault["faultCode"]);
        }
    }

    private function _dispatch($payload) {

        $data = null;

        // curl handle 
        $ch = curl_init(); 

        // uncomment to debug curl traffic
        //curl_setopt($ch, CURLOPT_VERBOSE, true);

        $headers[] = "Content-type: text/xml"; 
        $headers[] = "Accept: text/xml";

        // If the cookie is available we want to pass it along
        if ($this->xmlrpc_cookie != null) {
            $headers[] = "Cookie: XMLRPC_SESSION=" . $this->xmlrpc_cookie;
        }

        if ($this->x_forwarded_for != null) {
            $headers[] = "X-Forwarded-For: " . $this->x_forwarded_for;
        }

        curl_setopt($ch, CURLOPT_USERAGENT, "SecureXMLRPCClient/0.0.1");

        // Setup connection - Note libcurl ignores port in the url so port must be passes
        //  i.e. https://localhost:1339/ will not override the port option. -- possible enhancement 
        curl_setopt($ch, CURLOPT_URL, $this->_url);
        curl_setopt($ch, CURLOPT_PORT, $this->_port);

        // by default we want to check the peer certs correctly hoewever when using self-signed we need to set this to false
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $this->_tls);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $this->_tls);
        #curl_setopt($ch, CURLOPT_SSLVERSION, $this->_ssl_version); 

        // return header data (which we will parse for the "Set-Cooke")
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); 

        // Use post
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers); 
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);

        // Send request
        $response = curl_exec($ch);

        # todo - cleanup error handler
        if (curl_errno($ch)) { 

            $errno = curl_errno($ch);
            $error = curl_error($ch);

            curl_close($ch);
            throw new SXMLRPCSystemError($error, $errno);
        }

        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($code == 200) {
            $data = $this->_parse_response($response, $ch);
        } else {
            curl_close($ch);
            throw new Exception("HTTP Response Code Error", $code);
        }

        // cleanup handle
        curl_close($ch);

        if (is_array($data) AND xmlrpc_is_fault($data)) {
            $this->_raise_fault($data);
        }

        return $data;

    }

    function call($method, $args=array()) {

        $payload = xmlrpc_encode_request($method, $args); 

        return $this->_dispatch($payload);
    }


}


/*
$xmlrpc = new SecureXMLRPCClient("https://localhost/", 1337, null, 0); 

var_dump( $xmlrpc->call("auth.whoami") );
var_dump( $xmlrpc->call("auth.login", ["russell", "secret"]) );
var_dump( $xmlrpc->call("auth.whoami") );
var_dump( $xmlrpc->call("auth.setuid", ["steve"]) );
var_dump( $xmlrpc->call("auth.whoami") );
*/





?>
