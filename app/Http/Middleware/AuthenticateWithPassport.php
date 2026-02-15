<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateWithPassport
{
    /**
     * Bridge Passport Bearer token authentication to the web session guard.
     *
     * This middleware allows Fortify routes (which use auth:web) to accept
     * Passport Bearer tokens from external API clients. It resolves the
     * user from the Passport (api) guard and sets them on the web guard.
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! auth('web')->check()) {
            $user = auth('api')->user();

            if ($user) {
                auth('web')->login($user);
            }
        }

        return $next($request);
    }
}
