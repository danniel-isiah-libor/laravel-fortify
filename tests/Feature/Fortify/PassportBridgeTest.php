<?php

use App\Models\User;
use Illuminate\Support\Facades\Hash;

test('passport bearer token authenticates via middleware bridge', function () {
    $user = User::factory()->create([
        'password' => Hash::make('Password123!'),
    ]);

    $token = $user->createToken('test-token');

    $response = $this->withHeaders([
        'Authorization' => 'Bearer ' . $token->accessToken,
    ])->postJson('/user/confirm-password', [
        'password' => 'Password123!',
    ]);

    $response->assertStatus(201);
});
