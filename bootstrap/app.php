<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__ . '/../routes/web.php',
        api: __DIR__ . '/../routes/api.php',
        commands: __DIR__ . '/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->validateCsrfTokens(except: ['*']);

        // Ensure our Passport bridge middleware runs BEFORE the Authenticate
        // middleware. Laravel's middleware priority system would otherwise
        // sort Authenticate (which implements AuthenticatesRequests) first.
        $middleware->prependToPriorityList(
            \Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests::class,
            \App\Http\Middleware\AuthenticateWithPassport::class
        );
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        //
    })->create();
