<?php

namespace App\Http\Responses;

use Laravel\Fortify\Contracts\LogoutResponse as LogoutResponseContract;

class LogoutResponse implements LogoutResponseContract
{
    /**
     * Revoke the current Passport access token and return a no-content response.
     */
    public function toResponse($request)
    {
        $request->user('api')?->token()?->revoke();

        return response()->noContent();
    }
}
