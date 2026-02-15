<?php

use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Laravel\Passport\Passport;

/*
|--------------------------------------------------------------------------
| Password Update Tests (PUT /user/password)
|--------------------------------------------------------------------------
| Route middleware: web, AuthenticateWithPassport, auth:web
*/

test('authenticated user can update their password', function () {
    $user = User::factory()->create([
        'password' => Hash::make('CurrentPassword123!'),
    ]);

    Passport::actingAs($user);

    $response = $this->putJson('/user/password', [
        'current_password' => 'CurrentPassword123!',
        'password' => 'NewPassword123!',
        'password_confirmation' => 'NewPassword123!',
    ]);

    $response->assertSuccessful();

    $user->refresh();
    expect(Hash::check('NewPassword123!', $user->password))->toBeTrue();
});

test('password cannot be updated with wrong current password', function () {
    $user = User::factory()->create([
        'password' => Hash::make('CurrentPassword123!'),
    ]);

    Passport::actingAs($user);

    $response = $this->putJson('/user/password', [
        'current_password' => 'WrongPassword123!',
        'password' => 'NewPassword123!',
        'password_confirmation' => 'NewPassword123!',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['current_password']);
});

test('password cannot be updated with mismatched confirmation', function () {
    $user = User::factory()->create([
        'password' => Hash::make('CurrentPassword123!'),
    ]);

    Passport::actingAs($user);

    $response = $this->putJson('/user/password', [
        'current_password' => 'CurrentPassword123!',
        'password' => 'NewPassword123!',
        'password_confirmation' => 'DifferentPassword123!',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['password']);
});

test('password cannot be updated without current password', function () {
    $user = User::factory()->create();

    Passport::actingAs($user);

    $response = $this->putJson('/user/password', [
        'password' => 'NewPassword123!',
        'password_confirmation' => 'NewPassword123!',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['current_password']);
});

test('password cannot be updated with a weak new password', function () {
    $user = User::factory()->create([
        'password' => Hash::make('CurrentPassword123!'),
    ]);

    Passport::actingAs($user);

    $response = $this->putJson('/user/password', [
        'current_password' => 'CurrentPassword123!',
        'password' => '123',
        'password_confirmation' => '123',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['password']);
});

test('unauthenticated user cannot update password', function () {
    $response = $this->putJson('/user/password', [
        'current_password' => 'CurrentPassword123!',
        'password' => 'NewPassword123!',
        'password_confirmation' => 'NewPassword123!',
    ]);

    $response->assertStatus(401);
});
