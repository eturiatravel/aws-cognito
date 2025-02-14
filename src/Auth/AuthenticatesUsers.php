<?php

/*
 * This file is part of AWS Cognito Auth solution.
 *
 * (c) EllaiSys <support@ellaisys.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ellaisys\Cognito\Auth;

use Auth;
use GuzzleHttp\Exception\ClientException;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;

use Ellaisys\Cognito\AwsCognitoClient;

use Exception;
use Illuminate\Validation\ValidationException;
use Ellaisys\Cognito\Exceptions\AwsCognitoException;
use Ellaisys\Cognito\Exceptions\NoLocalUserException;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;


trait AuthenticatesUsers
{

    /**
     * Attempt to log the user into the application.
     *
     * @param \Illuminate\Support\Collection $request
     * @param \string $guard (optional)
     * @param \string $paramUsername (optional)
     * @param \string $paramPassword (optional)
     * @param \bool $isJsonResponse (optional)
     *
     * @return mixed
     */
    protected function attemptLogin(Collection $request,bool $isJsonResponse = false, string $guard = 'web', string $paramUsername = 'email', string $paramPassword = 'password', string $paramCode = 'code')
    {
        Log::info('Start login attempt');
        try {

            $keyUsername = 'email';
            $keyPassword = 'password';
            $keyCode = 'code';
            $rememberMe = $request->has('remember') ? $request['remember'] : false;

            //Generate credentials array
            if (empty($request[$paramCode])){
                $credentials = [
                    $keyUsername => $request[$paramUsername],
                    $keyPassword => $request[$paramPassword]
                ];
            } else {
                $credentials = [
                    $keyCode => $request[$paramCode]
                ];
            }

            Log::info('Start authenticating user via set Guards. Try to get AWS Claim');
            $claim = Auth::guard($guard)->attempt($credentials, $rememberMe);
            Log::info('End authenticating user. Resulted AWS Claim => ' . $claim );
        } catch (NoLocalUserException $e) {
            Log::error('AuthenticatesUsers:attemptLogin:NoLocalUserException');
            return $this->sendFailedLoginResponse($request, $e, $isJsonResponse);
        } catch (CognitoIdentityProviderException $e) {
            Log::error('AuthenticatesUsers:attemptLogin:CognitoIdentityProviderException');
            return $this->sendFailedCognitoResponse($e);
        } catch (ClientException $e) {
            Log::error('AuthenticatesUsers:attemptLogin:Exception');
            return $this->sendFailedCodeAuth($request, $e, $isJsonResponse);
        } catch (Exception $e) {
            Log::error('AuthenticatesUsers:attemptLogin:Exception');
            return $this->sendFailedLoginResponse($request, $e, $isJsonResponse);
        } //Try-catch ends
        Log::info('End login attempt');
        return $claim;
    } //Function ends





    /**
     * Handle Failed Cognito Exception
     *
     * @param CognitoIdentityProviderException $exception
     */
    private function sendFailedCognitoResponse(CognitoIdentityProviderException $exception)
    {
        throw ValidationException::withMessages([
            $this->username() => $exception->getAwsErrorMessage(),
        ]);
    } //Function ends


    /**
     * Handle Generic Exception
     *
     * @param \Collection $request
     * @param \Exception $exception
     */
    private function sendFailedLoginResponse(Collection $request, Exception $exception = null, bool $isJsonResponse = false)
    {
        $message = 'FailedLoginResponse';
        if (!empty($exception)) {
            $message = $exception->getMessage();
        } //End if

        if ($isJsonResponse) {
            return response()->json([
                'error' => 'cognito.validation.auth.failed',
                'message' => $message
            ], 400);
        } else {
            return redirect()
                ->withErrors([
                    'username' => $message,
                ]);
        } //End if

        throw new HttpException(400, $message);
    } //Function ends

    private function sendFailedCodeAuth(Collection $request, Exception $exception = null, bool $isJsonResponse = false)
    {
        $message = 'FailedAuth';
        if (!empty($exception)) {
            $message = (string) $exception->getResponse()->getBody();
        } //End if

        if ($isJsonResponse) {
            return response()->json([
                json_decode($message),
            ], 401);
        } else {
            return redirect()
                ->withErrors([
                    'username' => $message,
                ]);
        } //End if

        throw new HttpException(401, $message);
    }

} //Trait ends
