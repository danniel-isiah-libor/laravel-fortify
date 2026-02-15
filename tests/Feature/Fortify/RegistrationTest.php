<?php

use App\Models\User;

/*
|--------------------------------------------------------------------------
| Registration Tests (POST /register)
|--------------------------------------------------------------------------
| Route middleware: web, AuthenticateWithPassport, guest:web
| Response: Passport personal access token + user data (201)
*/

test('new user can register with valid data', function () {
    $response = $this->postJson('/register', [
        'name' => 'Test User',
        'email' => 'test@example.com',
        'password' => 'Password123!',
        'password_confirmation' => 'Password123!',
    ]);

    $response->assertStatus(201)
        ->assertJsonStructure(['user', 'token_type', 'access_token', 'expires_in'])
        ->assertJsonPath('token_type', 'Bearer');

    $this->assertDatabaseHas('users', [
        'name' => 'Test User',
        'email' => 'test@example.com',
    ]);
});

test('new user cannot register without name', function () {
    $response = $this->postJson('/register', [
        'email' => 'test@example.com',
        'password' => 'Password123!',
        'password_confirmation' => 'Password123!',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['name']);
});

test('new user cannot register without email', function () {
    $response = $this->postJson('/register', [
        'name' => 'Test User',
        'password' => 'Password123!',
        'password_confirmation' => 'Password123!',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['email']);
});

test('new user cannot register without password', function () {
    $response = $this->postJson('/register', [
        'name' => 'Test User',
        'email' => 'test@example.com',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['password']);
});

test('new user cannot register with invalid email', function () {
    $response = $this->postJson('/register', [
        'name' => 'Test User',
        'email' => 'not-an-email',
        'password' => 'Password123!',
        'password_confirmation' => 'Password123!',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['email']);
});

test('new user cannot register with mismatched password confirmation', function () {
    $response = $this->postJson('/register', [
        'name' => 'Test User',
        'email' => 'test@example.com',
        'password' => 'Password123!',
        'password_confirmation' => 'DifferentPassword123!',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['password']);
});

test('new user cannot register with an already existing email', function () {
    User::factory()->create(['email' => 'test@example.com']);

    $response = $this->postJson('/register', [
        'name' => 'Test User',
        'email' => 'test@example.com',
        'password' => 'Password123!',
        'password_confirmation' => 'Password123!',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['email']);
});

test('new user cannot register with a weak password', function () {
    $response = $this->postJson('/register', [
        'name' => 'Test User',
        'email' => 'test@example.com',
        'password' => '123',
        'password_confirmation' => '123',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['password']);
});

test('registration lowercases the email', function () {
    $response = $this->postJson('/register', [
        'name' => 'Test User',
        'email' => 'Test@Example.COM',
        'password' => 'Password123!',
        'password_confirmation' => 'Password123!',
    ]);

    $response->assertStatus(201);

    $this->assertDatabaseHas('users', [
        'email' => 'test@example.com',
    ]);
});
