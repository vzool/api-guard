<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Header Key
    |--------------------------------------------------------------------------
    |
    | This is the name of the variable that will provide us the API key in the
    | header
    |
    */
    'header_public_key' => 'X-Auth-EndPoint',
    'header_shared_key' => 'X-Auth-Token',
    
    'hmac_algo' => 'sha3-384', // for more algos see hash_hmac_algos(), http://php.net/manual/en/function.hash-hmac-algos.php

    'models' => [

        'api_key' => 'Vzool\ApiHmacGuard\Models\ApiKey',

    ],

];
