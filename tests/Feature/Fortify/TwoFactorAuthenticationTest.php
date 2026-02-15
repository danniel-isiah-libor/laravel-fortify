<?php

use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Laravel\Passport\Passport;
use PragmaRX\Google2FA\Google2FA;

/*
|--------------------------------------------------------------------------
| Two-Factor Authentication Tests
|--------------------------------------------------------------------------
| Enable/Disable/QR/Secret/Recovery routes → web, AuthenticateWithPassport, auth:web, password.confirm
| Confirm 2FA route                        → web, AuthenticateWithPassport, auth:web, password.confirm
| Two-factor challenge (login)             → web, AuthenticateWithPassport, guest:web, throttle:two-factor
| Response: Passport personal access token on successful 2FA challenge
*/

// ─── Enable Two-Factor Authentication ───────────────────────────────────────

test('authenticated user can enable two-factor authentication', function () {
    $user = User::factory()->create([
        'password' => Hash::make('Password123!'),
    ]);

    Passport::actingAs($user);

    // Confirm password first (required by password.confirm middleware)
    $this->postJson('/user/confirm-password', ['password' => 'Password123!'])
        ->assertStatus(201);

    $response = $this->postJson('/user/two-factor-authentication');

    $response->assertSuccessful();

    $user->refresh();
    expect($user->two_factor_secret)->not->toBeNull();
    expect($user->two_factor_recovery_codes)->not->toBeNull();
});

test('unauthenticated user cannot enable two-factor authentication', function () {
    $response = $this->postJson('/user/two-factor-authentication');

    $response->assertStatus(401);
});

test('two-factor authentication cannot be enabled without password confirmation', function () {
    $user = User::factory()->create();

    Passport::actingAs($user);

    $response = $this->postJson('/user/two-factor-authentication');

    // password.confirm middleware returns 423 for JSON requests
    $response->assertStatus(423);
});

// ─── Two-Factor QR Code ─────────────────────────────────────────────────────

test('authenticated user can get two-factor qr code after enabling 2fa', function () {
    $user = User::factory()->create([
        'password' => Hash::make('Password123!'),
    ]);

    Passport::actingAs($user);

    // Confirm password and enable 2FA
    $this->postJson('/user/confirm-password', ['password' => 'Password123!']);
    $this->postJson('/user/two-factor-authentication');

    $response = $this->getJson('/user/two-factor-qr-code');

    $response->assertSuccessful()
        ->assertJsonStructure(['svg', 'url']);
});

test('user without 2fa enabled gets empty response for qr code', function () {
    $user = User::factory()->create([
        'password' => Hash::make('Password123!'),
    ]);

    Passport::actingAs($user);

    // Confirm password but don't enable 2FA
    $this->postJson('/user/confirm-password', ['password' => 'Password123!']);

    $response = $this->getJson('/user/two-factor-qr-code');

    $response->assertSuccessful()
        ->assertJson([]);
});

// ─── Two-Factor Secret Key ──────────────────────────────────────────────────

test('authenticated user can get two-factor secret key', function () {
    $user = User::factory()->create([
        'password' => Hash::make('Password123!'),
    ]);

    Passport::actingAs($user);

    // Confirm password and enable 2FA
    $this->postJson('/user/confirm-password', ['password' => 'Password123!']);
    $this->postJson('/user/two-factor-authentication');

    $response = $this->getJson('/user/two-factor-secret-key');

    $response->assertSuccessful()
        ->assertJsonStructure(['secretKey']);
});

// ─── Confirm Two-Factor Authentication ──────────────────────────────────────

test('authenticated user can confirm two-factor authentication with valid code', function () {
    $user = User::factory()->create([
        'password' => Hash::make('Password123!'),
    ]);

    $google2fa = new Google2FA();
    $secret = $google2fa->generateSecretKey();

    $user->forceFill([
        'two_factor_secret' => encrypt($secret),
        'two_factor_recovery_codes' => encrypt(json_encode([
            'recovery-code-1',
            'recovery-code-2',
        ])),
    ])->save();

    Passport::actingAs($user);

    // Confirm password first
    $this->postJson('/user/confirm-password', ['password' => 'Password123!']);

    $validCode = $google2fa->getCurrentOtp($secret);

    $response = $this->postJson('/user/confirmed-two-factor-authentication', [
        'code' => $validCode,
    ]);

    $response->assertSuccessful();

    $user->refresh();
    expect($user->two_factor_confirmed_at)->not->toBeNull();
});

test('two-factor authentication cannot be confirmed with invalid code', function () {
    $user = User::factory()->create([
        'password' => Hash::make('Password123!'),
    ]);

    $google2fa = new Google2FA();
    $secret = $google2fa->generateSecretKey();

    $user->forceFill([
        'two_factor_secret' => encrypt($secret),
        'two_factor_recovery_codes' => encrypt(json_encode(['recovery-code-1'])),
    ])->save();

    Passport::actingAs($user);

    // Confirm password first
    $this->postJson('/user/confirm-password', ['password' => 'Password123!']);

    $response = $this->postJson('/user/confirmed-two-factor-authentication', [
        'code' => '000000',
    ]);

    $response->assertStatus(422)
        ->assertJsonValidationErrors(['code']);
});

// ─── Two-Factor Recovery Codes ──────────────────────────────────────────────

test('authenticated user can get two-factor recovery codes', function () {
    $user = User::factory()->create([
        'password' => Hash::make('Password123!'),
    ]);

    $google2fa = new Google2FA();
    $secret = $google2fa->generateSecretKey();
    $recoveryCodes = ['code-1', 'code-2', 'code-3', 'code-4'];

    $user->forceFill([
        'two_factor_secret' => encrypt($secret),
        'two_factor_recovery_codes' => encrypt(json_encode($recoveryCodes)),
        'two_factor_confirmed_at' => now(),
    ])->save();

    Passport::actingAs($user);

    // Confirm password first
    $this->postJson('/user/confirm-password', ['password' => 'Password123!']);

    $response = $this->getJson('/user/two-factor-recovery-codes');

    $response->assertSuccessful()
        ->assertJson($recoveryCodes);
});

test('authenticated user can regenerate two-factor recovery codes', function () {
    $user = User::factory()->create([
        'password' => Hash::make('Password123!'),
    ]);

    $google2fa = new Google2FA();
    $secret = $google2fa->generateSecretKey();

    $user->forceFill([
        'two_factor_secret' => encrypt($secret),
        'two_factor_recovery_codes' => encrypt(json_encode(['old-code-1', 'old-code-2'])),
        'two_factor_confirmed_at' => now(),
    ])->save();

    Passport::actingAs($user);

    // Confirm password first
    $this->postJson('/user/confirm-password', ['password' => 'Password123!']);

    $oldRecoveryCodes = json_decode(decrypt($user->two_factor_recovery_codes), true);

    $response = $this->postJson('/user/two-factor-recovery-codes');

    $response->assertSuccessful();

    $user->refresh();
    $newRecoveryCodes = json_decode(decrypt($user->two_factor_recovery_codes), true);

    expect($newRecoveryCodes)->not->toBe($oldRecoveryCodes);
});

// ─── Disable Two-Factor Authentication ──────────────────────────────────────

test('authenticated user can disable two-factor authentication', function () {
    $user = User::factory()->create([
        'password' => Hash::make('Password123!'),
    ]);

    $google2fa = new Google2FA();
    $secret = $google2fa->generateSecretKey();

    $user->forceFill([
        'two_factor_secret' => encrypt($secret),
        'two_factor_recovery_codes' => encrypt(json_encode(['code-1'])),
        'two_factor_confirmed_at' => now(),
    ])->save();

    Passport::actingAs($user);

    // Confirm password first
    $this->postJson('/user/confirm-password', ['password' => 'Password123!']);

    $response = $this->deleteJson('/user/two-factor-authentication');

    $response->assertSuccessful();

    $user->refresh();
    expect($user->two_factor_secret)->toBeNull();
    expect($user->two_factor_recovery_codes)->toBeNull();
    expect($user->two_factor_confirmed_at)->toBeNull();
});

test('unauthenticated user cannot disable two-factor authentication', function () {
    $response = $this->deleteJson('/user/two-factor-authentication');

    $response->assertStatus(401);
});

// ─── Two-Factor Challenge (Login with 2FA) ──────────────────────────────────

test('user with 2fa enabled is prompted for two-factor challenge on login', function () {
    $google2fa = new Google2FA();
    $secret = $google2fa->generateSecretKey();

    User::factory()->create([
        'email' => 'test@example.com',
        'password' => Hash::make('Password123!'),
        'two_factor_secret' => encrypt($secret),
        'two_factor_recovery_codes' => encrypt(json_encode(['recovery-code-1', 'recovery-code-2'])),
        'two_factor_confirmed_at' => now(),
    ]);

    $response = $this->postJson('/login', [
        'email' => 'test@example.com',
        'password' => 'Password123!',
    ]);

    $response->assertSuccessful()
        ->assertJsonPath('two_factor', true);
});

test('user can complete two-factor challenge with valid totp code', function () {
    $google2fa = new Google2FA();
    $secret = $google2fa->generateSecretKey();

    $user = User::factory()->create([
        'email' => 'test@example.com',
        'password' => Hash::make('Password123!'),
        'two_factor_secret' => encrypt($secret),
        'two_factor_recovery_codes' => encrypt(json_encode(['recovery-code-1'])),
        'two_factor_confirmed_at' => now(),
    ]);

    $validCode = $google2fa->getCurrentOtp($secret);

    $response = $this->withSession([
        'login.id' => $user->id,
        'login.remember' => false,
    ])->postJson('/two-factor-challenge', [
        'code' => $validCode,
    ]);

    $response->assertSuccessful()
        ->assertJsonStructure(['user', 'token_type', 'access_token', 'expires_in'])
        ->assertJsonPath('token_type', 'Bearer');
});

test('user can complete two-factor challenge with a valid recovery code', function () {
    $google2fa = new Google2FA();
    $secret = $google2fa->generateSecretKey();
    $recoveryCodes = ['recovery-code-1', 'recovery-code-2', 'recovery-code-3'];

    $user = User::factory()->create([
        'email' => 'test@example.com',
        'password' => Hash::make('Password123!'),
        'two_factor_secret' => encrypt($secret),
        'two_factor_recovery_codes' => encrypt(json_encode($recoveryCodes)),
        'two_factor_confirmed_at' => now(),
    ]);

    $response = $this->withSession([
        'login.id' => $user->id,
        'login.remember' => false,
    ])->postJson('/two-factor-challenge', [
        'recovery_code' => 'recovery-code-1',
    ]);

    $response->assertSuccessful()
        ->assertJsonStructure(['user', 'token_type', 'access_token', 'expires_in']);

    // Verify the used recovery code is consumed
    $user->refresh();
    $remainingCodes = json_decode(decrypt($user->two_factor_recovery_codes), true);
    expect($remainingCodes)->not->toContain('recovery-code-1');
});

test('two-factor challenge fails with invalid code', function () {
    $google2fa = new Google2FA();
    $secret = $google2fa->generateSecretKey();

    $user = User::factory()->create([
        'password' => Hash::make('Password123!'),
        'two_factor_secret' => encrypt($secret),
        'two_factor_recovery_codes' => encrypt(json_encode(['code-1'])),
        'two_factor_confirmed_at' => now(),
    ]);

    $response = $this->withSession([
        'login.id' => $user->id,
        'login.remember' => false,
    ])->postJson('/two-factor-challenge', [
        'code' => '000000',
    ]);

    $response->assertStatus(422);
});

test('two-factor challenge fails with invalid recovery code', function () {
    $google2fa = new Google2FA();
    $secret = $google2fa->generateSecretKey();

    $user = User::factory()->create([
        'password' => Hash::make('Password123!'),
        'two_factor_secret' => encrypt($secret),
        'two_factor_recovery_codes' => encrypt(json_encode(['valid-recovery-code'])),
        'two_factor_confirmed_at' => now(),
    ]);

    $response = $this->withSession([
        'login.id' => $user->id,
        'login.remember' => false,
    ])->postJson('/two-factor-challenge', [
        'recovery_code' => 'invalid-recovery-code',
    ]);

    $response->assertStatus(422);
});

test('two-factor challenge fails without session login id', function () {
    $response = $this->postJson('/two-factor-challenge', [
        'code' => '123456',
    ]);

    $response->assertStatus(422);
});
