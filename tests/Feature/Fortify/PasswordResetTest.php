<?php

use App\Models\User;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;

/*
|--------------------------------------------------------------------------
| Password Reset Tests (POST /forgot-password, POST /reset-password)
|--------------------------------------------------------------------------
| Route middleware: web, AuthenticateWithPassport, guest:web
*/

test('password reset link can be requested', function () {
    Notification::fake();

    $user = User::factory()->create(['email' => 'test@example.com']);

    $response = $this->postJson('/forgot-password', [
        'email' => 'test@example.com',
    ]);

    $response->assertSuccessful();

    Notification::assertSentTo($user, ResetPassword::class);
});

test('password reset link cannot be requested without email', function () {
    $response = $this->postJson('/forgot-password', []);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['email']);
});

test('password reset link requires a valid email', function () {
    $response = $this->postJson('/forgot-password', [
        'email' => 'not-an-email',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['email']);
});

test('password can be reset with a valid token', function () {
    $user = User::factory()->create(['email' => 'test@example.com']);

    $token = Password::broker()->createToken($user);

    $response = $this->postJson('/reset-password', [
        'token' => $token,
        'email' => 'test@example.com',
        'password' => 'NewPassword123!',
        'password_confirmation' => 'NewPassword123!',
    ]);

    $response->assertSuccessful();

    $user->refresh();
    expect(Hash::check('NewPassword123!', $user->password))->toBeTrue();
});

test('password cannot be reset with an invalid token', function () {
    User::factory()->create(['email' => 'test@example.com']);

    $response = $this->postJson('/reset-password', [
        'token' => 'invalid-token',
        'email' => 'test@example.com',
        'password' => 'NewPassword123!',
        'password_confirmation' => 'NewPassword123!',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['email']);
});

test('password cannot be reset without a token', function () {
    $response = $this->postJson('/reset-password', [
        'email' => 'test@example.com',
        'password' => 'NewPassword123!',
        'password_confirmation' => 'NewPassword123!',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['token']);
});

test('password cannot be reset with mismatched confirmation', function () {
    $user = User::factory()->create(['email' => 'test@example.com']);

    $token = Password::broker()->createToken($user);

    $response = $this->postJson('/reset-password', [
        'token' => $token,
        'email' => 'test@example.com',
        'password' => 'NewPassword123!',
        'password_confirmation' => 'DifferentPassword123!',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['password']);
});

test('password cannot be reset for non-existent email', function () {
    $response = $this->postJson('/reset-password', [
        'token' => 'some-token',
        'email' => 'nonexistent@example.com',
        'password' => 'NewPassword123!',
        'password_confirmation' => 'NewPassword123!',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['email']);
});
