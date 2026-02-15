<?php

use App\Models\User;
use Laravel\Passport\Passport;

/*
|--------------------------------------------------------------------------
| Profile Information Tests (PUT /user/profile-information)
|--------------------------------------------------------------------------
| Route middleware: web, AuthenticateWithPassport, auth:web
*/

test('authenticated user can update their profile information', function () {
    $user = User::factory()->create();

    Passport::actingAs($user);

    $response = $this->putJson('/user/profile-information', [
        'name' => 'Updated Name',
        'email' => $user->email,
    ]);

    $response->assertSuccessful();

    $user->refresh();
    expect($user->name)->toBe('Updated Name');
});

test('authenticated user can update their email', function () {
    $user = User::factory()->create([
        'email' => 'old@example.com',
        'email_verified_at' => now(),
    ]);

    Passport::actingAs($user);

    $response = $this->putJson('/user/profile-information', [
        'name' => $user->name,
        'email' => 'new@example.com',
    ]);

    $response->assertSuccessful();

    $user->refresh();
    expect($user->email)->toBe('new@example.com');
    // Email verification should be reset since User implements MustVerifyEmail
    expect($user->email_verified_at)->toBeNull();
});

test('profile information cannot be updated without name', function () {
    $user = User::factory()->create();

    Passport::actingAs($user);

    $response = $this->putJson('/user/profile-information', [
        'email' => $user->email,
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['name']);
});

test('profile information cannot be updated without email', function () {
    $user = User::factory()->create();

    Passport::actingAs($user);

    $response = $this->putJson('/user/profile-information', [
        'name' => 'Updated Name',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['email']);
});

test('profile information cannot be updated with invalid email', function () {
    $user = User::factory()->create();

    Passport::actingAs($user);

    $response = $this->putJson('/user/profile-information', [
        'name' => 'Updated Name',
        'email' => 'not-a-valid-email',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['email']);
});

test('profile information cannot be updated with an email that already exists', function () {
    User::factory()->create(['email' => 'existing@example.com']);
    $user = User::factory()->create();

    Passport::actingAs($user);

    $response = $this->putJson('/user/profile-information', [
        'name' => 'Updated Name',
        'email' => 'existing@example.com',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['email']);
});

test('unauthenticated user cannot update profile information', function () {
    $response = $this->putJson('/user/profile-information', [
        'name' => 'Updated Name',
        'email' => 'test@example.com',
    ]);

    $response->assertStatus(401);
});

test('profile update keeps email verified when email is unchanged', function () {
    $user = User::factory()->create([
        'email' => 'test@example.com',
        'email_verified_at' => now(),
    ]);

    Passport::actingAs($user);

    $response = $this->putJson('/user/profile-information', [
        'name' => 'Updated Name',
        'email' => 'test@example.com',
    ]);

    $response->assertSuccessful();

    $user->refresh();
    expect($user->email_verified_at)->not->toBeNull();
});
