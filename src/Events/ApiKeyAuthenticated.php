<?php

namespace Vzool\ApiHmacGuard\Events;

use Vzool\ApiHmacGuard\Models\ApiKey;
use Illuminate\Queue\SerializesModels;

class ApiKeyAuthenticated
{
    use SerializesModels;

    public $request;

    public $apiKey;

    /**
     * Create a new event instance.
     *
     * @param $request
     * @param ApiKey $apiKey
     */
    public function __construct($request, ApiKey $apiKey)
    {
        $this->request = $request;
        $this->apiKey = $apiKey;
    }
}
