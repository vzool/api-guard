<?php

namespace Vzool\ApiHmacGuard\Http\Middleware;

use Carbon\Carbon;
use Vzool\ApiHmacGuard\Events\ApiKeyAuthenticated;
use Vzool\ApiHmacGuard\Models\Device;
use Closure;

class AuthenticateApiKey
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request $request
     * @param Closure $next
     * @param  string|null $guard
     * @return mixed
     */
    public function handle($request, Closure $next, $guard = null)
    {
        $apiPublicKeyValue = $request->header(config('apiguard.header_public_key', 'X-Auth-EndPoint'));
        $apiSharedKeyValue = $request->header(config('apiguard.header_shared_key', 'X-Auth-Token'));

        $apiKey = app(config('apiguard.models.api_key', 'Vzool\ApiHmacGuard\Models\ApiKey'))
            ->where('public_key', $apiPublicKeyValue)
            ->first();

        // access the key record by public key
        if (empty($apiKey)) {
            return $this->unauthorizedResponse();
        }

        // calculate the shared key and compare it with the user token,
        // then check if client shared key(Token) matches server one.
        // Timing attack safe string comparison
        if (!hash_equals($apiKey->sharedKey(), $apiSharedKeyValue)) {
            return $this->unauthorizedResponse();
        }

        // Update this api key's last_used_at and last_ip_address
        $apiKey->update([
            'last_used_at'    => Carbon::now(),
            'last_ip_address' => $request->ip(),
        ]);

        $apikeyable = $apiKey->apikeyable;

        // Bind the user or object to the request
        // By doing this, we can now get the specified user through the request object in the controller using:
        // $request->user()
        $request->setUserResolver(function () use ($apikeyable) {
            return $apikeyable;
        });

        // Attach the apikey object to the request
        $request->apiKey = $apiKey;

        event(new ApiKeyAuthenticated($request, $apiKey));

        return $next($request);
    }

    protected function unauthorizedResponse()
    {
        return response([
            'error' => [
                'code'      => '401',
                'http_code' => 'GEN-UNAUTHORIZED',
                'message'   => 'Unauthorized.',
            ],
        ], 401);
    }
}
