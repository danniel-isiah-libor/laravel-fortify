<?php

namespace App\Http\Responses;

use Laravel\Fortify\Contracts\RegisterResponse as RegisterResponseContract;

class RegisterResponse implements RegisterResponseContract
{
    /**
     * Return a JSON response with a Passport personal access token after registration.
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
        ], 201);
    }
}
