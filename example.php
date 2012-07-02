<?php

//example controller function 
// for use with Annotator Authentication (https://github.com/okfn/annotator)

public function generate_token($user_id){
     $this->load->library("JWT");
     $CONSUMER_KEY = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
	    $CONSUMER_SECRET = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
	    $CONSUMER_TTL = 86400;
	    echo $this->jwt->encode(array(
	      'consumerKey'=>$CONSUMER_KEY,
	      'userId'=>$user_id,
	      'issuedAt'=>date(DATE_ISO8601, strtotime("now")),
	      'ttl'=>$CONSUMER_TTL
	    ), $CONSUMER_SECRET);
	}

?>
