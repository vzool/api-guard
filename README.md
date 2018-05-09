ApiHmacGuard
========

### Fork overview points:

1- API tokens should never be saved in the database, which help us secure users token and protect them against impersonate user account by using tokens that leaked from database if breach take place.

2- Database will save a `public_key` which is an endpoint to access key pairs record, this key should be unique and indexed.

3- Database will save a `private_key` which will be kept private at server side.

4- Token which is a `shared_key` will be generated every time when the request happen.

5- Token will be generated on the fly by Hmac and using Application Key `config('app.key')` as server private key with `private_key` which considered a client private key on server side.

6- Default Hmac algo is `sha3-384`, there are many algo out [there](http://php.net/manual/en/function.hash-hmac-algos.php).

7- If you change Hmac alog, the key length will be different which depends on algo itself.

8- The `Middleware` will expect two keys as headers which are:

- `X-Auth-EndPoint`: this is a `public_key`
- `X-Auth-Token`: this is a `shared_key`

So, you should send these two keys to your clients and make them send back to server.

9- Never, never send or expose `priavte_key`.

[![Latest Stable Version](https://poser.pugx.org/chrisbjr/api-guard/v/stable)](https://packagist.org/packages/chrisbjr/api-guard) [![Total Downloads](https://poser.pugx.org/chrisbjr/api-guard/downloads)](https://packagist.org/packages/chrisbjr/api-guard)

[![Join the chat at https://gitter.im/chrisbjr/api-guard](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/chrisbjr/api-guard?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

A simple way of authenticating your APIs with API keys using Laravel. This package uses the following libraries:

- philsturgeon's [Fractal](https://github.com/thephpleague/fractal)
- maximebeaudoin's [api-response](https://github.com/ellipsesynergie/api-response)

## Laravel 5.3, 5.4 and 5.5 is finally supported!

**Laravel 5.3.x onwards: `~4.*`

**Laravel 5.1.x to 5.2.x: [`~3.*`](https://github.com/vzool/api-hmac-guard/blob/3.1/README.md)

**Laravel 5.1.x: `~2.*`

**Laravel 4.2.x: [`~1.*`](https://github.com/vzool/api-hmac-guard/tree/laravel4) (Recently updated version for Laravel 4. Please note that there are namespace changes here)

**Laravel 4.2.x: [`0.*`](https://github.com/vzool/api-hmac-guard/tree/v0.7) (The version that most of you are using)

## Quick start

### Installation for Laravel 5.3 to 5.4

Run `composer require chrisbjr/api-guard 4.*`

In your `config/app.php` add `Vzool\ApiHmacGuard\Providers\ApiGuardServiceProvider` to the end of the `providers` array

```php
'providers' => array(

    ...
    Vzool\ApiHmacGuard\Providers\ApiGuardServiceProvider::class,
),
```

Now publish the migration and configuration files for api-guard:

    $ php artisan vendor:publish --provider="Vzool\ApiHmacGuard\Providers\ApiGuardServiceProvider"

Then run the migration:

    $ php artisan migrate

It will setup  `api_keys` table.

### Generating your first API key

Once you're done with the required setup, you can now generate your first API key.

Run the following command to generate an API key:

`php artisan api-key:generate`

Generally, the `ApiKey` object is a polymorphic object meaning this can belong to more than one other model.

To generate an API key that is linked to another object (a "user", for example), you can do the following:

+`php artisan api-key:generate --id=1 --type="App\User"`

To specify that a model can have API keys, you can attach the `Apikeyable` trait to the model:

```php
use Vzool\ApiHmacGuard\Models\Mixins\Apikeyable;

class User extends Model
{
    use Apikeyable;

    ...
}

```

This will attach the following methods to the model:

```php
// Get the API keys of the object
$user->apiKeys();

// Create an API key for the object
$user->createApiKey();
```

To generate an API key from within your application, you can use the following method in the `ApiKey` model:

```php
$apiKey = Vzool\ApiHmacGuard\Models\ApiKey::make()

// Attach a model to the API key
$apiKey = Vzool\ApiHmacGuard\Models\ApiKey::make($model)
```

To access client keys:

```php

$apiKey->clientKeys()

```

## Usage

You can start using ApiGuard by simply attaching the `auth.apikey` middleware to your API route:

```php
Route::middleware(['auth.apikey'])->get('/test', function (Request $request) {
    return $request->user(); // Returns the associated model to the API key
});
```

This effectively secures your API with an API key which needs to specified in the `X-Authorization` header. This can be configured in `config/apiguard.php`.

Here is a sample cURL command to demonstrate:

```
curl -X GET \
  http://apiguard.dev/api/test \
  -H 'x-authorization: api-key-here'
```

You might also want to attach this middleware to your `api` middleware group in your `app/Http/Kernel.php` to take advantage of other Laravel features such as
throttling.

```php
/**
 * The application's route middleware groups.
 *
 * @var array
 */
protected $middlewareGroups = [
    ...

    'api' => [
        'throttle:60,1',
        'bindings',
        'auth.apikey',
    ],
];
```

If you noticed in the basic example, you can also access the attached model to the API key by calling `$request->user()`. We are attaching the related model in
this method because in most use cases, this is actually the user.

### Unauthorized Requests

Unauthorized requests will get a `401` status response with the following JSON:

```json
{
  "error": {
    "code": "401",
    "http_code": "GEN-UNAUTHORIZED",
    "message": "Unauthorized."
  }
}
```

### ApiGuardController

The `ApiGuardController` takes advantage of [Fractal](http://fractal.thephpleague.com/) and [api-response](https://github.com/ellipsesynergie/api-response) libraries.

This enables us to easily create APIs with models and use transformers to give a standardized JSON response.

Here is an example:

Let's say you have the following model:

```php
use Illuminate\Database\Eloquent\Model;

class Book extends Model
{
    protected $fillable = [
        'name',
    ];
}
```

You can make a basic controller which will return all books like this:

```php
use Vzool\ApiHmacGuard\Http\Controllers\ApiGuardController;
use App\Transformers\BookTransformer;
use App\Book;

class BooksController extends ApiGuardController
{
    public function all()
    {
        $books = Book::all();

        return $this->response->withCollection($books, new BookTransformer);
    }
}
```

Now, you'll need to make the transformer for your Book object. Transformers help with defining and manipulating the variables you want to return to your JSON response.

```php
use League\Fractal\TransformerAbstract;
use App\Book;

class BookTransformer extends TransformerAbstract
{
    public function transform(Book $book)
    {
        return [
            'id'         => $book->id,
            'name'       => $book->name,
            'created_at' => $book->created_at,
            'updated_at' => $book->updated_at,
        ];
    }
}
```

Once you have this accessible in your routes, you will get the following response from the controller:

```json
{
  "data": {
    "id": 1,
    "title": "The Great Adventures of Chris",
    "created_at": {
      "date": "2017-05-25 18:54:18",
      "timezone_type": 3,
      "timezone": "UTC"
    },
    "updated_at": {
      "date": "2017-05-25 18:54:18",
      "timezone_type": 3,
      "timezone": "UTC"
    }
  }
}
```

More examples can be found on the Github page: [https://github.com/ellipsesynergie/api-response](https://github.com/ellipsesynergie/api-response).

To learn more about transformers, visit the PHP League's documentation on Fractal: [Fractal](http://fractal.thephpleague.com/)

### API Validation Responses

ApiGuard comes with a request class that can handle validation of requests for you and throw a standard response.

You can create a `Request` class as you usually do but in order to get a standard JSON response you'll have to extend the `ApiGuardFormRequest` class.

```php
use Vzool\ApiHmacGuard\Http\Requests\ApiGuardFormRequest;

class BookStoreRequest extends ApiGuardFormRequest
{
    public function authorize()
    {
        return true;
    }

    public function rules()
    {
        return [
            'name' => 'required',
        ];
    }
}
```

Now you can use this in your controller as you normally do with Laravel:

```php
use Vzool\ApiHmacGuard\Http\Controllers\ApiGuardController;
use App\Transformers\BookTransformer;
use App\Book;

class BooksController extends ApiGuardController
{
    public function store(BookStoreRequest $request)
    {
        // Request should already be validated

        $book = Book::create($request->all())

        return $this->response->withItem($book, new BookTransformer);
    }
}
```

If the request failed to pass the validation rules, it will return with a response like the following:

```json
{
  "error": {
    "code": "GEN-UNPROCESSABLE",
    "http_code": 422,
    "message": {
      "name": [
        "The name field is required."
      ]
    }
  }
}
```
