<?php

use App\Models\User;
use Laravel\Passport\Passport;

/*
|--------------------------------------------------------------------------
| Authentication Tests (POST /login, POST /logout)
|--------------------------------------------------------------------------
| Login route middleware:  web, AuthenticateWithPassport, guest:web, throttle:login
| Logout route middleware: web, AuthenticateWithPassport, auth:web
| Response: Passport personal access token + user data
*/

test('user can login with valid credentials', function () {
    User::factory()->create([
        'email' => 'test@example.com',
        'password' => bcrypt('Password123!'),
    ]);

    $response = $this->postJson('/login', [
        'email' => 'test@example.com',
        'password' => 'Password123!',
    ]);

    $response->assertSuccessful()
        ->assertJsonStructure(['user', 'token_type', 'access_token', 'expires_in'])
        ->assertJsonPath('token_type', 'Bearer');
});

test('user cannot login with invalid password', function () {
    User::factory()->create([
        'email' => 'test@example.com',
        'password' => bcrypt('Password123!'),
    ]);

    $response = $this->postJson('/login', [
        'email' => 'test@example.com',
        'password' => 'WrongPassword!',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['email']);
});

test('user cannot login with non-existent email', function () {
    $response = $this->postJson('/login', [
        'email' => 'nonexistent@example.com',
        'password' => 'Password123!',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['email']);
});

test('user cannot login without email', function () {
    $response = $this->postJson('/login', [
        'password' => 'Password123!',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['email']);
});

test('user cannot login without password', function () {
    User::factory()->create(['email' => 'test@example.com']);

    $response = $this->postJson('/login', [
        'email' => 'test@example.com',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['password']);
});

test('authenticated user can logout', function () {
    $user = User::factory()->create();

    Passport::actingAs($user);

    $response = $this->postJson('/logout');

    $response->assertStatus(204);
});

test('unauthenticated user cannot logout', function () {
    $response = $this->postJson('/logout');

    $response->assertStatus(401);
});

test('login is rate limited after too many attempts', function () {
    User::factory()->create([
        'email' => 'test@example.com',
        'password' => bcrypt('Password123!'),
    ]);

    for ($i = 0; $i < 5; $i++) {
        $this->postJson('/login', [
            'email' => 'test@example.com',
            'password' => 'WrongPassword!',
        ]);
    }

    $response = $this->postJson('/login', [
        'email' => 'test@example.com',
        'password' => 'WrongPassword!',
    ]);

    $response->assertStatus(429);
});
