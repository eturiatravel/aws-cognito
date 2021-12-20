<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) EllaiSys <support@ellaisys.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ellaisys\Cognito\Guards;

use Aws\Result as AwsResult;
use Illuminate\Http\Request;
use Illuminate\Auth\TokenGuard;
use Illuminate\Support\Facades\Log;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\Authenticatable;

use Ellaisys\Cognito\AwsCognito;
use Ellaisys\Cognito\AwsCognitoClient;
use Ellaisys\Cognito\AwsCognitoClaim;

use Exception;
use Ellaisys\Cognito\Exceptions\NoLocalUserException;
use Ellaisys\Cognito\Exceptions\InvalidUserModelException;
use Ellaisys\Cognito\Exceptions\AwsCognitoException;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;

class CognitoOAuth2TokenGuard extends CognitoTokenGuard
{

    protected $keyUsername;
    protected $client;
    protected $cognito;
    protected $claim;
    protected $keyCode;


    public function __construct(
        AwsCognito       $cognito,
        AwsCognitoClient $client,
        Request          $request,
        UserProvider     $provider = null,
        string           $keyUsername = 'email',
        string           $keyCode = 'code'
    )
    {
        parent::__construct($cognito, $client, $request, $provider, $keyUsername, $keyCode);
    }


    protected function hasValidCredentials($user, $credentials): bool
    {
        $result = $this->client->authenticateWithCode($credentials[$this->keyCode]);

        if (!empty($result) && $result instanceof AwsResult) {
            $this->claim = new AwsCognitoClaim($result, $user, $credentials[$this->keyUsername]);
            return ($this->claim) ? true : false;
        } else {
            return false;
        }

        return false;
    }
}