<?php

namespace App\Http\Responses;

use Laravel\Fortify\Contracts\LogoutResponse as LogoutResponseContract;

class LogoutResponse implements LogoutResponseContract
{
    /**
     * Return a no-content response after logout.
     *
     * The frontend is responsible for discarding the stored access token.
     * Token expiration or a dedicated revocation endpoint can handle
     * server-side token invalidation if needed.
     */
    public function toResponse($request)
    {
        return response()->noContent();
    }
}
