<?php

namespace App\Http\Responses;

use Laravel\Fortify\Contracts\TwoFactorLoginResponse as TwoFactorLoginResponseContract;

class TwoFactorLoginResponse implements TwoFactorLoginResponseContract
{
    /**
     * Return a JSON response with a Passport personal access token after two-factor authentication.
     */
    public function toResponse($request)
    {
        $user = $request->user();
        $tokenResult = $user->createToken('api-token');

        return response()->json([
            'user' => $user,
            'token_type' => $tokenResult->tokenType,
            'access_token' => $tokenResult->accessToken,
            'expires_in' => $tokenResult->expiresIn,
        ]);
    }
}
