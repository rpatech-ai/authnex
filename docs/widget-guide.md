# JS Login Widget Guide

The AuthNex JS Widget provides a drop-in login/register form for any website.

## Installation

### CDN (recommended)

```html
<script src="https://cdn.authnex.com/widget.min.js"></script>
```

### NPM

```bash
npm install @authnex/widget
```

```javascript
import { AuthNex } from '@authnex/widget';
```

## Basic Setup

```html
<div id="authnex-login"></div>
<script src="https://cdn.authnex.com/widget.min.js"></script>
<script>
  AuthNex.init({
    container: '#authnex-login',
    apiUrl: 'https://your-authnex-instance.com',
    tenant: 'your-tenant-slug',
  });
</script>
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `container` | string | (required) | CSS selector for the widget container |
| `apiUrl` | string | (required) | Your AuthNex API URL |
| `tenant` | string | `''` | Tenant slug (can also use `data-tenant` attribute) |
| `apiKey` | string | `undefined` | API key (optional, for server-side usage) |
| `theme` | string | `'light'` | `'light'` or `'dark'` |
| `logo` | string | `undefined` | URL to your logo image |
| `title` | string | `'Welcome'` | Widget heading text |
| `showRegister` | boolean | `true` | Show registration form |
| `showForgotPassword` | boolean | `true` | Show forgot password link |
| `showRememberMe` | boolean | `true` | Show remember me checkbox |
| `redirectUrl` | string | `undefined` | URL to redirect after login |
| `primaryColor` | string | `undefined` | Custom primary color (CSS variable) |

## Events

### onLogin

Fired after successful login.

```javascript
AuthNex.init({
  container: '#authnex-login',
  apiUrl: 'https://auth.example.com',
  onLogin: (user, tokens) => {
    console.log('Logged in:', user.email);
    console.log('Access token:', tokens.access_token);
    window.location.href = '/dashboard';
  }
});
```

### onRegister

Fired after successful registration.

```javascript
AuthNex.onRegister((user) => {
  console.log('Registered:', user.email);
  // User needs to verify email before logging in
});
```

### onLogout

Fired when user logs out.

```javascript
AuthNex.onLogout(() => {
  console.log('User logged out');
  window.location.href = '/';
});
```

### onError

Fired on any authentication error.

```javascript
AuthNex.onError((error) => {
  console.error('Auth error:', error.message);
  // Custom error handling
});
```

## API Methods

### AuthNex.getUser()

Returns the current user or `null`.

```javascript
const user = AuthNex.getUser();
if (user) {
  console.log('Logged in as:', user.email);
}
```

### AuthNex.getAccessToken()

Returns the current access token.

```javascript
const token = AuthNex.getAccessToken();
fetch('/api/data', {
  headers: { 'Authorization': `Bearer ${token}` }
});
```

### AuthNex.isAuthenticated()

Check if a user is currently logged in.

```javascript
if (AuthNex.isAuthenticated()) {
  // Show protected content
}
```

### AuthNex.logout()

Log out the current user.

```javascript
await AuthNex.logout();
```

### AuthNex.destroy()

Remove the widget and clean up timers.

```javascript
AuthNex.destroy();
```

## Dark Theme

```html
<script>
  AuthNex.init({
    container: '#authnex-login',
    apiUrl: 'https://auth.example.com',
    theme: 'dark',
  });
</script>
```

## Custom Styling

The widget uses CSS custom properties that you can override:

```css
.authnex-widget {
  --authnex-primary: #8b5cf6;
  --authnex-primary-hover: #7c3aed;
  --authnex-bg: #fafafa;
  --authnex-text: #111827;
  --authnex-input-border: #d1d5db;
  --authnex-input-bg: #ffffff;
  --authnex-link: #8b5cf6;
}
```

## Token Storage

Tokens are stored in `localStorage`:

- `authnex_tokens` — Access and refresh tokens
- `authnex_user` — Cached user data

The widget automatically refreshes the access token 60 seconds before expiry.

## Framework Examples

### React

```jsx
import { useEffect } from 'react';

function LoginPage() {
  useEffect(() => {
    const widget = AuthNex.init({
      container: '#auth',
      apiUrl: process.env.REACT_APP_AUTH_URL,
      tenant: 'my-tenant',
      onLogin: (user) => {
        navigate('/dashboard');
      },
    });
    return () => widget.destroy();
  }, []);

  return <div id="auth" />;
}
```

### Vue

```vue
<template>
  <div id="authnex-login"></div>
</template>

<script setup>
import { onMounted, onUnmounted } from 'vue';

let widget;
onMounted(() => {
  widget = AuthNex.init({
    container: '#authnex-login',
    apiUrl: import.meta.env.VITE_AUTH_URL,
    tenant: 'my-tenant',
    onLogin: () => router.push('/dashboard'),
  });
});
onUnmounted(() => widget?.destroy());
</script>
```
