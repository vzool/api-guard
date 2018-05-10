<?php

namespace Vzool\ApiHmacGuard\Models;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Request;

class ApiKey extends Model
{
    use SoftDeletes;

    protected $guarded  = ['private_key'];

    protected $fillable = [
        'public_key',
        'apikeyable_id',
        'apikeyable_type',
        'last_ip_address',
        'last_used_at',
    ];

    /**
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo
     */
    public function apikeyable()
    {
        return $this->morphTo();
    }

    /**
     * @return array
     */
    public function clientKeys()
    {
        return [
            'endpoint' => $this->public_key,
            'token' => self::calculateSharedKey($this->private_key),
        ];
    }

    /**
     * A method to access shared key
     *
     * @return string
     */
    public function sharedKey()
    {
        return self::calculateSharedKey($this->private_key);
    }

    /**
     * A method to access public key
     *
     * @return string
     */
    public function publicKey()
    {
        return $this->public_key;
    }

    /**
     * A method to access private key
     *
     * @return string
     */
    public function privateKey()
    {
        return null;
    }

    /**
     * @param $apikeyable
     *
     * @return ApiKey
     */
    public static function make($apikeyable)
    {
        $apiKey = new ApiKey([
            'public_key'      => self::generatePublicKey(),
            'apikeyable_id'   => $apikeyable->id,
            'apikeyable_type' => get_class($apikeyable),
            'last_ip_address' => Request::ip(),
            'last_used_at'    => Carbon::now(),
        ]);

        $apiKey->private_key = self::generatePrivateKey();

        $apiKey->save();

        return $apiKey;
    }

    /**
     * A sure method to generate a unique API key
     *
     * @return string
     */
    public static function generatePublicKey()
    {
        do {
            $newKey = '-' . substr(uniqid(1) .'-'. str_random(34), 0, 48) .'-';
        } // Already in the DB? Fail. Try again
        while (self::publicKeyExists($newKey));

        return $newKey;
    }

    /**
     * A method to generate a private key
     *
     * @return string
     */
    public static function generatePrivateKey()
    {
        return '-' . substr(str_random(34).'-'.uniqid(1), 0, 48) .'-';
    }

    /**
     * A method to generate a shared key
     * 
     * @param $public_key
     * @return string
     */
    public static function generateSharedKey($public_key)
    {

        $apiKey = self::where('public_key', '=', $public_key)->limit(1)->first();

        if(!$apiKey){
            return 'API key not fount';
        }
        
        return self::calculateSharedKey($apiKey->private_key);
    }

    /**
     * A method to calculate the shared key
     *
     * @param $private_key
     * @param $custom_app_key
     * @return string
     */
    public static function calculateSharedKey($private_key, $custom_app_key = null){

        // get laravel application as private key

        $app_key = config('app.key', $custom_app_key);

        if(!$app_key){
            return 'Your application does not has an app key, please generate it using this command: `php artisan key:generate`';
        }

        $algo = config('apiguard.hmac_algo', 'sha3-384');

        $shared_key = hash_hmac($algo, $private_key, $app_key, false);

        return $shared_key;
    }

    /**
     * Checks whether a public key exists in the database or not
     *
     * @param $key
     * @return bool
     */
    public static function publicKeyExists($key)
    {
        $apiKeyCount = self::where('public_key', '=', $key)->limit(1)->count();

        if ($apiKeyCount > 0) return true;

        return false;
    }

    /*============================================================*/
    /* Some elequoent overrides to protect public & private keys */
    /*==========================================================*/

    /**
     * Set the private_key for once.
     *
     * @param  string  $value
     * @return void
     */
    public function setPrivateKeyAttribute($value)
    {
        if(!$this->private_key){

            $this->attributes['private_key'] = $value;
        }
    }

    /**
     * Set the public_key for once.
     *
     * @param  string  $value
     * @return void
     */
    public function setPublicKeyAttribute($value)
    {
        if(!$this->public_key){

            $this->attributes['public_key'] = $value;
        }
    }
}
