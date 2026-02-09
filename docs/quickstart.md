# Quick Start: Add Auth to Your PHP App in 5 Minutes

Get your PHP application secured with AuthNex in just a few steps.

## Prerequisites

- PHP 8.1+
- Composer installed
- An AuthNex account ([Sign up free](../customer-portal/index.html#signup))

## Step 1: Install the SDK

```bash
composer require authnex/php-sdk
```

## Step 2: Initialize AuthNex

Create a file or add to your bootstrap:

```php
<?php
require 'vendor/autoload.php';

$auth = new \AuthNex\AuthNex([
    'api_url' => 'https://your-authnex-instance.com',
    'tenant'  => 'your-tenant-slug',
    'api_key' => 'ak_xxxxxxxx_xxxxxxxx',  // From your portal
]);
```

## Step 3: Protect Routes

Add this to any page that requires authentication:

```php
// Redirects to /login if not authenticated
$auth->protect();

// Get the current user
$user = $auth->getUser();
echo "Welcome, " . $user['email'];
```

## Step 4: Add Login

Create a login page:

```php
<?php
require 'vendor/autoload.php';

$auth = new \AuthNex\AuthNex([
    'api_url' => 'https://your-authnex-instance.com',
    'tenant'  => 'your-tenant-slug',
    'api_key' => 'ak_xxxxxxxx_xxxxxxxx',
]);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $result = $auth->login($_POST['email'], $_POST['password']);
        header('Location: /dashboard');
        exit;
    } catch (\AuthNex\AuthNexException $e) {
        $error = $e->getMessage();
    }
}
?>
<form method="POST">
    <?php if (isset($error)): ?>
        <div class="error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    <input type="email" name="email" placeholder="Email" required />
    <input type="password" name="password" placeholder="Password" required />
    <button type="submit">Login</button>
</form>
```

## Step 5: Role-Based Access

Restrict pages by role:

```php
$auth->protect();

// Only admins can access this page
$auth->requireRole('admin');

// Or check permissions
$auth->requirePermission('users:create');

// Or check without throwing
if ($auth->hasRole('admin')) {
    // Show admin controls
}
```

## Using the Middleware

For more control, use the middleware:

```php
$middleware = new \AuthNex\Middleware($auth, [
    'login_url' => '/login',
    'excluded_paths' => ['/login', '/register', '/public/**'],
    'role_map' => [
        '/admin/**' => 'admin',
    ],
    'permission_map' => [
        '/api/users' => 'users:read',
    ],
]);

// Call at the start of your application
$middleware->handle();
```

## Using the JS Widget Instead

If you prefer a drop-in login form, use the JS widget:

```html
<div id="authnex-login"></div>
<script src="https://cdn.authnex.com/widget.min.js"></script>
<script>
  AuthNex.init({
    container: '#authnex-login',
    apiUrl: 'https://your-authnex-instance.com',
    tenant: 'your-tenant-slug',
    onLogin: (user) => {
      window.location.href = '/dashboard';
    }
  });
</script>
```

## Next Steps

- [Core Concepts](concepts.md) — Understand tenants, roles, tokens
- [API Reference](api-reference.md) — Full endpoint documentation
- [JS Widget Guide](widget-guide.md) — Customize the login widget
