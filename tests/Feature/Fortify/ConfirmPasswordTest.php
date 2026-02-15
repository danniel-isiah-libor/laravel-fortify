<?php

use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Laravel\Passport\Passport;

/*
|--------------------------------------------------------------------------
| Confirm Password Tests
|--------------------------------------------------------------------------
| POST /user/confirm-password          → web, AuthenticateWithPassport, auth:web
| GET  /user/confirmed-password-status → web, AuthenticateWithPassport, auth:web
*/

test('authenticated user can confirm their password', function () {
    $user = User::factory()->create([
        'password' => Hash::make('Password123!'),
    ]);

    Passport::actingAs($user);

    $response = $this->postJson('/user/confirm-password', [
        'password' => 'Password123!',
    ]);

    $response->assertStatus(201);
});

test('password confirmation fails with wrong password', function () {
    $user = User::factory()->create([
        'password' => Hash::make('Password123!'),
    ]);

    Passport::actingAs($user);

    $response = $this->postJson('/user/confirm-password', [
        'password' => 'WrongPassword!',
    ]);

    $response->assertStatus(422);
});

test('password confirmation fails without password', function () {
    $user = User::factory()->create();

    Passport::actingAs($user);

    $response = $this->postJson('/user/confirm-password', [
        'password' => '',
    ]);

    $response->assertStatus(422);
});

test('confirmed password status returns false when not recently confirmed', function () {
    $user = User::factory()->create();

    Passport::actingAs($user);

    $response = $this->getJson('/user/confirmed-password-status');

    $response->assertSuccessful()
        ->assertJsonPath('confirmed', false);
});

test('confirmed password status returns true after password confirmation', function () {
    $user = User::factory()->create([
        'password' => Hash::make('Password123!'),
    ]);

    Passport::actingAs($user);

    // First confirm the password
    $this->postJson('/user/confirm-password', [
        'password' => 'Password123!',
    ])->assertStatus(201);

    // Then check status
    $response = $this->getJson('/user/confirmed-password-status');

    $response->assertSuccessful()
        ->assertJsonPath('confirmed', true);
});

test('unauthenticated user cannot confirm password', function () {
    $response = $this->postJson('/user/confirm-password', [
        'password' => 'Password123!',
    ]);

    $response->assertStatus(401);
});

test('unauthenticated user cannot check confirmed password status', function () {
    $response = $this->getJson('/user/confirmed-password-status');

    $response->assertStatus(401);
});
