<?php defined('BASEPATH') OR exit('No direct script access allowed');

class Jwt {
    public $key     = '.-.)!';
    public $header  = '{"alg":"HS256","typ":"JWT"}';

    private $alg;
    private $hash;
    private $data;

    public function __construct(){
        $CI = &get_instance();

        $this->key = $CI->config->item('encryption_key');

        log_message('info', 'Jwt Class Initialized @ '. current_url());
    }

    public function encode($data){
        $payload = json_encode($data);

        return $this->_encode($this->header, $payload, $this->key);
    }

    public function decode($token){
        return json_decode($this->_decode($token, $this->key));
    }

    private function _encode($header, $payload, $key){
        $this->data = $this->urlEncode($header) . '.' . $this->urlEncode($payload);

        return $this->data . '.' . $this->jws($header, $key);
    }

    private function _decode($token, $key){
        list($header, $payload, $signature) = explode('.', $token);

        $this->data = $header . '.' . $payload;

        if($signature == $this->jws($this->urlDecode($header), $key)){
            return $this->urlDecode($payload);
        }

        exit('Invalid Signature');
    }

    private function jws($header, $key){
        $json   = json_decode($header);

        $this->setAlgorithm($json->alg);

        if($this->alg == 'plaintext') return '';

        return $this->urlEncode(hash_hmac($this->hash, $this->data, $key, true));
    }

    private function setAlgorithm($algorithm) {
        switch($algorithm[0]) {
            case 'n':
                $this->alg = 'plaintext';
                break;
            case 'H':
                $this->alg = 'HMAC';
                break;
            // By now, the only native is HMAC
            /*
            case R:
                $this->alg = 'RSA';
                break;
            case E:
                $this->alg = 'ECDSA';
                break;
            */
            default:
              die('RSA and ECDSA not implemented yet! (.^.i)');
              break;
        }

        switch($algorithm[2]) {
            case 'a':
                $this->alg = 'plaintext';
                break;
            case 2:
                $hash = 'sha256';
                break;
            case 3:
                $hash = 'sha384';
                break;
            case 5:
                $hash = 'sha512';
                break;
        }

        if(in_array($hash, hash_algos())) $this->hash = $hash;
    }

    private function urlEncode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function urlDecode($data) {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}
