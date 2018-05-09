<?php

namespace Vzool\ApiHmacGuard\Console\Commands;

use Vzool\ApiHmacGuard\Models\ApiKey;
use Illuminate\Console\Command;

class GenerateApiKey extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'api-key:generate
                            {--id= : ID of the model you want to bind to this API key}
                            {--type= : The class name of the model you want to bind to this API key}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Generate an API pair keys';

    /**
     * Create a new command instance.
     *
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return mixed
     */
    public function handle()
    {
        $apiKeyableId = $this->option('id');
        $apiKeyableType = $this->option('type');

        $apiKey = new ApiKey([
            'public_key'      => ApiKey::generatePublicKey(),
            'private_key'     => ApiKey::generatePrivateKey(),
            'apikeyable_id'   => $apiKeyableId,
            'apikeyable_type' => $apiKeyableType,
        ]);

        $apiKey->save();

        $this->info('====================================================');
        $this->info('An API keys was created with the following details: ');
        $this->info('====================================================');
        $this->info('Public Key: ' . $apiKey->public_key);
        $this->info('Shared Key: ' . ApiKey::calculateSharedKey($apiKey->private_key));
        $this->info('====================================================');
        $this->info('In order to use these keys just set them in the headers:');
        $this->info('Header of Public Key: ' . config('apiguard.header_public_key'));
        $this->info('Header of Shared Key: ' . config('apiguard.header_shared_key'));
        $this->info('====================================================');

        return;
    }
}
