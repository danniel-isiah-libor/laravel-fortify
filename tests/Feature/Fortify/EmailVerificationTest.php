<?php

use App\Models\User;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\URL;
use Laravel\Passport\Passport;

/*
|--------------------------------------------------------------------------
| Email Verification Tests
|--------------------------------------------------------------------------
| POST /email/verification-notification  → web, AuthenticateWithPassport, auth:web, throttle:6,1
| GET  /email/verify/{id}/{hash}         → web, AuthenticateWithPassport, auth:web, signed, throttle:6,1
*/

test('email verification notification can be sent', function () {
    Notification::fake();

    $user = User::factory()->unverified()->create();

    Passport::actingAs($user);

    $response = $this->postJson('/email/verification-notification');

    $response->assertStatus(202);

    Notification::assertSentTo($user, VerifyEmail::class);
});

test('email verification notification is not sent if already verified', function () {
    Notification::fake();

    $user = User::factory()->create(); // verified by default

    Passport::actingAs($user);

    $response = $this->postJson('/email/verification-notification');

    // Already verified - Fortify returns 204
    $response->assertStatus(204);

    Notification::assertNotSentTo($user, VerifyEmail::class);
});

test('email can be verified with a valid signed url', function () {
    $user = User::factory()->unverified()->create();

    $verificationUrl = URL::temporarySignedRoute(
        'verification.verify',
        now()->addMinutes(60),
        ['id' => $user->id, 'hash' => sha1($user->getEmailForVerification())]
    );

    Passport::actingAs($user);

    $response = $this->getJson($verificationUrl);

    $response->assertSuccessful();

    $user->refresh();
    expect($user->hasVerifiedEmail())->toBeTrue();
});

test('email cannot be verified with an invalid hash', function () {
    $user = User::factory()->unverified()->create();

    $verificationUrl = URL::temporarySignedRoute(
        'verification.verify',
        now()->addMinutes(60),
        ['id' => $user->id, 'hash' => 'invalid-hash']
    );

    Passport::actingAs($user);

    $response = $this->getJson($verificationUrl);

    $response->assertStatus(403);

    $user->refresh();
    expect($user->hasVerifiedEmail())->toBeFalse();
});

test('email cannot be verified without authentication', function () {
    $user = User::factory()->unverified()->create();

    $verificationUrl = URL::temporarySignedRoute(
        'verification.verify',
        now()->addMinutes(60),
        ['id' => $user->id, 'hash' => sha1($user->getEmailForVerification())]
    );

    $response = $this->getJson($verificationUrl);

    $response->assertStatus(401);
});

test('email verification notification requires authentication', function () {
    $response = $this->postJson('/email/verification-notification');

    $response->assertStatus(401);
});
