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
use GuzzleHttp\Exception\ClientException;
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


    public function attempt(array $credentials = [], $remember = false)
    {
        try {
            $result = $this->client->authenticateWithCode($credentials[$this->keyCode]);
            $cognitoUser = $this->getUserFromToken($result);
            $this->claim = new AwsCognitoClaim($result, $cognitoUser, $credentials[$this->keyUsername]);

            $this->lastAttempted = $user = $this->provider->retrieveByCredentials($cognitoUser);

            //Check if the user exists in local data store
            if (!($user instanceof Authenticatable) && config('cognito.add_missing_local_user_sso')) {
                $this->createLocalUser($credentials);
                $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);
            } elseif (!($user instanceof Authenticatable)) {
                throw new NoLocalUserException();
            } //End if

            return $this->login($user);


            return false;
        } catch (NoLocalUserException $e) {
            Log::error('CognitoTokenGuard:attempt:NoLocalUserException:');
            throw $e;
        } catch (CognitoIdentityProviderException $e) {
            Log::error('CognitoTokenGuard:attempt:CognitoIdentityProviderException:'.$e->getAwsErrorCode());

            //Set proper route
            if (!empty($e->getAwsErrorCode())) {
                $errorCode = 'CognitoIdentityProviderException';
                switch ($e->getAwsErrorCode()) {
                    case 'PasswordResetRequiredException':
                        $errorCode = 'cognito.validation.auth.reset_password';
                        break;

                    case 'NotAuthorizedException':
                        $errorCode = 'cognito.validation.auth.user_unauthorized';
                        break;

                    default:
                        $errorCode = $e->getAwsErrorCode();
                        break;
                } //End switch

                return response()->json(['error' => $errorCode, 'message' => $e->getAwsErrorCode() ], 400);
            } //End if

            return $e->getAwsErrorCode();
        } catch (AwsCognitoException $e) {
            Log::error('CognitoTokenGuard:attempt:AwsCognitoException:'. $e->getMessage());
            throw $e;
        } catch (ClientException $e) {
            Log::error($e->getResponse()->getBody()->getContents());
            throw $e;
        } catch (Exception $e) {
            Log::error('CognitoTokenGuard:attempt:Exception:'.$e->getMessage());
            throw $e;
        }
    }

    private function getUserFromToken($token)
    {
        $idToken = json_decode((string) $token->getBody())->id_token;
        $tokenParts = explode(".", $idToken);
        $tokenPayload = base64_decode($tokenParts[1]);
        $jwtPayload = json_decode($tokenPayload);
        return [
            "name" => $jwtPayload->name,
            "email" => $jwtPayload->email,
            "id" => $jwtPayload['cognito:username']
        ];
    }
}