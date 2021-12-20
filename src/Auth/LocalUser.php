<?php

namespace Ellaisys\Cognito\Auth;

use Illuminate\Support\Facades\Log;

trait LocalUser
{

    /**
     * Create a local user if one does not exist.
     *
     * @param array $credentials
     * @return mixed
     */
    protected function createLocalUser($credentials)
    {
        Log::info('Start creating new user.');
        $userModel = config('cognito.sso_user_model');
        $user = $userModel::create($credentials);
        Log::info('New user created.');
        return $user;
    } //Function ends
}