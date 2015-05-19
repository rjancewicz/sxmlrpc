<?php

define("XMLRPC_COOKIE", "XMLRPC_SESSION");

class SecureXMLRPCClient {

    private $xmlrpc_cookie = null;
    private $_url = null;
    private $_port = null;

    // todo configure SSL options passed to libcurl
    public function __construct($url="https://127.0.0.1/RPC2", $port=1337, $proxy=false, $ssl=null) {
        
        $this->_url = $url;
        $this->_port = $port;
        $this->_proxy = $proxy;

        if ($proxy && array_key_exists($_COOKIE, XMLRPC_COOKIE)) {
            $this->xmlrpc_cookie = $_COOKIE["XMLRPC_COOKIE"];
        }
    }

    private function _parse_headers($text) {

        $headers = array();

        foreach (explode("\r\n", $text) as $index => $line) {
            if ($index === 0) {
                $headers["HTTP"] = [$line];
            } else {
                list($key, $value) = explode(': ', $line, 2);

                if (array_key_exists($key, $headers)) {
                    $headers[$key][] = $value;
                } else {
                    $headers[$key] = [$value];
                }
            }
        }

        return $headers;
    }

    // https://tools.ietf.org/html/rfc6265#section-5.2
    static private function _parse_cookie($cookie) {

        static $COOKIE_AV_PAIRS = ["Expires", "Domain", "Path"];
        static $COOKIE_AV_SINGLES = ["Secure", "HttpOnly"];

        $cookies = [];
        $cookies["VALUES"] = [];

        $morsels = explode(";", $cookie);

        foreach ($morsels as $j => $morsel) {

            $morsel = trim($morsel);

            if (in_array($morsel, $COOKIE_AV_SINGLES)) {
                // skip for now
            } else {

                if (stripos($morsel, "=")) {

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

        if (array_key_exists("Set-Cookie", $headers)) {
            foreach ($headers["Set-Cookie"] as $i => $str_cookie) {

                $cookie = SecureXMLRPCClient::_parse_cookie($str_cookie);

                $values = $cookie["VALUES"];

                foreach ($values as $key => $pair) {
                    if (strcasecmp($key, XMLRPC_COOKIE) === 0) {
                        $this->xmlrpc_cookie = $pair;
                        break;
                    }
                }
            }
        }

        if ($this->_proxy) {
            setcookie(XMLRPC_COOKIE, $this->xmlrpc_cookie);
        }

    }

    private function _parse_response($payload, $ch) {

        $hsize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);

        $str_headers = substr($payload, 0, $hsize);
        $body = substr($payload, $hsize);

        $headers = $this->_parse_headers($str_headers);

        $this->_init_session($headers);

        return xmlrpc_decode($body);
    }

    private function _dispatch($payload) {

        $data = null;

        // curl handle 
        $ch = curl_init(); 

        //curl_setopt($ch, CURLOPT_VERBOSE, true);

        $headers[] = "Content-type: text/xml"; 
        $headers[] = "Accept: text/xml";

        if ($this->xmlrpc_cookie != null) {
            $headers[] = "Cookie: XMLRPC_SESSION=" . $this->xmlrpc_cookie;
        }

        curl_setopt($ch, CURLOPT_USERAGENT, "SecureXMLRPCClient/0.0.1");

        curl_setopt($ch, CURLOPT_URL, $this->_url);
        curl_setopt($ch, CURLOPT_PORT, $this->_port);

        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);

        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); 

        curl_setopt($ch, CURLOPT_POST, true);

        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers); 
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);

        $response = curl_exec($ch);

        # todo - cleanup error handler
        if (curl_errno($ch)) { 
            print "Error: " . curl_error($ch) . "\n"; 
        }

        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($code == 200) {
            $data = $this->_parse_response($response, $ch);
        } else {
            # we will raise a fault here 
        }

        curl_close($ch);

        return $data;

    }

    function call($method, $args=array()) {

        $payload = xmlrpc_encode_request($method, $args); 

        return $this->_dispatch($payload);
    }


}


$xmlrpc = new SecureXMLRPCClient("https://localhost/", 1337); 

var_dump( $xmlrpc->call("auth.whoami") );
var_dump( $xmlrpc->call("auth.login", ["russell", "secret"]) );
var_dump( $xmlrpc->call("auth.whoami") );
var_dump( $xmlrpc->call("auth.setuid", ["steve"]) );
var_dump( $xmlrpc->call("auth.whoami") );





?>
