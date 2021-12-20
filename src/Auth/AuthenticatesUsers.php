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
        try {
            //Get key fields
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

            //Authenticate User
            $claim = Auth::guard($guard)->attempt($credentials, $rememberMe);

        } catch (NoLocalUserException $e) {
            Log::error('AuthenticatesUsers:attemptLogin:NoLocalUserException');
            return $this->sendFailedLoginResponse($request, $e, $isJsonResponse);
        } catch (CognitoIdentityProviderException $e) {
            Log::error('AuthenticatesUsers:attemptLogin:CognitoIdentityProviderException');
            return $this->sendFailedCognitoResponse($e);
        } catch (Exception $e) {
            Log::error('AuthenticatesUsers:attemptLogin:Exception');
            return $this->sendFailedLoginResponse($request, $e, $isJsonResponse);
        } //Try-catch ends

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

} //Trait ends
