<?php

/*
|--------------------------------------------------------------------------
| Test Case
|--------------------------------------------------------------------------
|
| The closure you provide to your test functions is always bound to a specific PHPUnit test
| case class. By default, that class is "PHPUnit\Framework\TestCase". Of course, you may
| need to change it using the "pest()" function to bind a different classes or traits.
|
*/

pest()->extend(Tests\TestCase::class)
    ->use(Illuminate\Foundation\Testing\RefreshDatabase::class)
    ->beforeEach(function () {
        // Generate Passport encryption keys (once, persisted to storage/)
        if (! file_exists(storage_path('oauth-private.key'))) {
            $this->artisan('passport:keys', ['--force' => true, '--no-interaction' => true]);
        }

        // Create a Passport personal access client (needed per test due to RefreshDatabase)
        app(\Laravel\Passport\ClientRepository::class)
            ->createPersonalAccessGrantClient('Test Personal Access Client');
    })
    ->in('Feature');

/*
|--------------------------------------------------------------------------
| Expectations
|--------------------------------------------------------------------------
|
| When you're writing tests, you often need to check that values meet certain conditions. The
| "expect()" function gives you access to a set of "expectations" methods that you can use
| to assert different things. Of course, you may extend the Expectation API at any time.
|
*/

expect()->extend('toBeOne', function () {
    return $this->toBe(1);
});

/*
|--------------------------------------------------------------------------
| Functions
|--------------------------------------------------------------------------
|
| While Pest is very powerful out-of-the-box, you may have some testing code specific to your
| project that you don't want to repeat in every file. Here you can also expose helpers as
| global functions to help you to reduce the number of lines of code in your test files.
|
*/

function something()
{
    // ..
}

/**
 * Authenticate the test request with a real Passport Bearer token.
 *
 * Creates a personal access token for the given user and sets the
 * Authorization header for all subsequent requests in the current test.
 */
function passportActingAs(App\Models\User $user): string
{
    $token = $user->createToken('test-token');

    test()->withHeaders([
        'Authorization' => 'Bearer ' . $token->accessToken,
    ]);

    return $token->accessToken;
}
