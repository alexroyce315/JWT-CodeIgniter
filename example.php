<?php defined('BASEPATH') OR ('No direct script access allowed');

class Example extends MA_Controller {
    
    public function __construct() {
        parent::__construct();
        log_message('info', 'Example Class Initialized');
    }
    
    public function token($userId = 'demo') {
        $this->load->library('Jwt');
        echo $this->jwt->encode(array(
            'userId'  => $userId
        ));
    }
}
