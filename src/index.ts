// Date: 2025-02-07
// Author: Alok
// File: src/index.ts
// Purpose: Main worker entry, route handling, middleware chain

import { Env, AuthContext } from './types';
import { AuthService } from './auth';
import { AdminService } from './admin';
import { Middleware } from './middleware';
import { JWTService } from './jwt';
import { Utils } from './utils';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const middleware = new Middleware(env);
    const auth = new AuthService(env);
    const admin = new AdminService(env);
    const jwt = new JWTService(env);
    const utils = new Utils(env);

    await Promise.all([middleware.init(), auth.init(), jwt.init()]);

    try {
      // CORS preflight
      const corsResp = middleware.cors(request);
      if (corsResp) return corsResp;

      const url = new URL(request.url);
      const path = url.pathname;
      const method = request.method;

      // Global rate limit
      const rlResp = await middleware.rateLimit(request, { requests: 100, window: 60 });
      if (rlResp) return rlResp;

      let response: Response;

      // === PUBLIC AUTH ENDPOINTS ===
      if (path === '/api/auth/setup' && method === 'POST') {
        const body = await request.json() as any;
        const result = await auth.setup(body, utils.getClientIP(request));
        response = utils.successResponse(result, 201);
      }
      else if (path === '/api/auth/login' && method === 'POST') {
        const body = await request.json() as any;
        const result = await auth.login(body, utils.getClientIP(request), utils.getUserAgent(request));
        response = utils.successResponse(result);
      }
      else if (path === '/api/auth/register' && method === 'POST') {
        const body = await request.json() as any;
        const user = await auth.register(body, utils.getClientIP(request));
        response = utils.successResponse({ user }, 201);
      }
      else if (path === '/api/auth/verify-email' && method === 'POST') {
        await auth.verifyEmail(await request.json() as any);
        response = utils.successResponse({ message: 'Email verified' });
      }
      else if (path === '/api/auth/forgot-password' && method === 'POST') {
        const body = await request.json() as any;
        await auth.requestPasswordReset(body.email, utils.getClientIP(request));
        response = utils.successResponse({ message: 'If the email exists, a reset link was sent' });
      }
      else if (path === '/api/auth/reset-password' && method === 'POST') {
        await auth.resetPassword(await request.json() as any);
        response = utils.successResponse({ message: 'Password reset successful' });
      }
      else if (path === '/api/auth/refresh' && method === 'POST') {
        const body = await request.json() as any;
        const result = await auth.refreshToken(body.refresh_token, utils.getClientIP(request));
        response = utils.successResponse(result);
      }
      else if (path === '/api/auth/jwks' && method === 'GET') {
        response = new Response(JSON.stringify(await jwt.getJWKS()), {
          headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=86400' },
        });
      }
      // === PROTECTED AUTH ENDPOINTS ===
      else if (path === '/api/auth/logout' && method === 'POST') {
        const context = await middleware.authenticate(request);
        await auth.logout(context.token!, context.user!.id);
        response = utils.successResponse({ message: 'Logged out' });
      }
      else if (path === '/api/auth/change-password' && method === 'POST') {
        const context = await middleware.authenticate(request);
        const body = await request.json() as any;
        await auth.changePassword(context.user!.id, body.current_password, body.new_password);
        response = utils.successResponse({ message: 'Password changed' });
      }
      // === USER PROFILE ===
      else if (path === '/api/user/profile' && method === 'GET') {
        const context = await middleware.authenticate(request);
        const { password_hash, ...safe } = context.user!;
        response = utils.successResponse({ user: safe });
      }
      else if (path === '/api/user/profile' && method === 'PUT') {
        const context = await middleware.authenticate(request);
        const body = await request.json() as any;
        const updated = await env.DB.prepare(`UPDATE users SET metadata = ? WHERE id = ? RETURNING *`)
          .bind(JSON.stringify(body.metadata || {}), context.user!.id).first();
        response = utils.successResponse({ user: updated });
      }
      // === GDPR SELF-SERVICE ===
      else if (path === '/api/user/export' && method === 'GET') {
        const context = await middleware.authenticate(request);
        const data = await admin.exportUserData(
          { ...context, permissions: [...(context.permissions || []), 'users:read'] },
          context.user!.id
        );
        response = utils.successResponse(data);
      }
      // === ADMIN ENDPOINTS ===
      else if (path.startsWith('/api/admin/')) {
        const context = await middleware.authenticate(request);
        await middleware.requireTenant(request, context);

        // Users
        if (path === '/api/admin/users' && method === 'GET') {
          const p = Object.fromEntries(url.searchParams);
          response = utils.successResponse(await admin.listUsers(context, {
            page: parseInt(p.page || '1'), limit: parseInt(p.limit || '20'), search: p.search, status: p.status,
          }));
        }
        else if (path === '/api/admin/users/export' && method === 'GET') {
          const p = Object.fromEntries(url.searchParams);
          response = utils.successResponse(await admin.bulkExportUsers(context, { status: p.status }));
        }
        else if (path === '/api/admin/users/import' && method === 'POST') {
          const body = await request.json() as any;
          response = utils.successResponse(await admin.bulkImportUsers(context, body.users));
        }
        else if (path.match(/^\/api\/admin\/users\/\d+$/) && method === 'GET') {
          const userId = parseInt(path.split('/').pop()!);
          response = utils.successResponse({ user: await admin.getUser(context, userId) });
        }
        else if (path === '/api/admin/users' && method === 'POST') {
          const body = await request.json() as any;
          response = utils.successResponse({ user: await admin.createUser(context, body) }, 201);
        }
        else if (path.match(/^\/api\/admin\/users\/\d+$/) && method === 'PUT') {
          const userId = parseInt(path.split('/').pop()!);
          response = utils.successResponse({ user: await admin.updateUser(context, userId, await request.json() as any) });
        }
        else if (path.match(/^\/api\/admin\/users\/\d+$/) && method === 'DELETE') {
          await admin.deleteUser(context, parseInt(path.split('/').pop()!));
          response = utils.successResponse({ message: 'User deleted' });
        }
        else if (path.match(/^\/api\/admin\/users\/\d+\/lock$/) && method === 'POST') {
          const body = await request.json() as any;
          await admin.lockUser(context, parseInt(path.split('/')[4]), body.reason);
          response = utils.successResponse({ message: 'User locked' });
        }
        else if (path.match(/^\/api\/admin\/users\/\d+\/unlock$/) && method === 'POST') {
          await admin.unlockUser(context, parseInt(path.split('/')[4]));
          response = utils.successResponse({ message: 'User unlocked' });
        }
        else if (path.match(/^\/api\/admin\/users\/\d+\/force-reset$/) && method === 'POST') {
          await admin.forcePasswordReset(context, parseInt(path.split('/')[4]));
          response = utils.successResponse({ message: 'Password reset forced' });
        }
        // Sessions/devices
        else if (path.match(/^\/api\/admin\/users\/\d+\/sessions$/) && method === 'GET') {
          const sessions = await admin.getUserSessions(context, parseInt(path.split('/')[4]));
          response = utils.successResponse({ sessions });
        }
        else if (path.match(/^\/api\/admin\/users\/\d+\/sessions\/[^/]+$/) && method === 'DELETE') {
          const parts = path.split('/');
          await admin.revokeUserSession(context, parseInt(parts[4]), parts[6]);
          response = utils.successResponse({ message: 'Session revoked' });
        }
        // GDPR export
        else if (path.match(/^\/api\/admin\/users\/\d+\/export$/) && method === 'GET') {
          response = utils.successResponse(await admin.exportUserData(context, parseInt(path.split('/')[4])));
        }
        // Roles
        else if (path === '/api/admin/roles' && method === 'GET') {
          response = utils.successResponse({ roles: await admin.listRoles(context) });
        }
        else if (path === '/api/admin/roles' && method === 'POST') {
          const body = await request.json() as any;
          response = utils.successResponse({ role: await admin.createRole(context, body) }, 201);
        }
        else if (path.match(/^\/api\/admin\/users\/\d+\/roles$/) && method === 'POST') {
          const body = await request.json() as any;
          await admin.assignUserRole(context, parseInt(path.split('/')[4]), body.role_id);
          response = utils.successResponse({ message: 'Role assigned' });
        }
        else if (path.match(/^\/api\/admin\/users\/\d+\/roles\/\d+$/) && method === 'DELETE') {
          const parts = path.split('/');
          await admin.removeUserRole(context, parseInt(parts[4]), parseInt(parts[6]));
          response = utils.successResponse({ message: 'Role removed' });
        }
        // Tenants
        else if (path === '/api/admin/tenants' && method === 'GET') {
          response = utils.successResponse({ tenants: await admin.listTenants(context) });
        }
        else if (path === '/api/admin/tenants' && method === 'POST') {
          response = utils.successResponse({ tenant: await admin.createTenant(context, await request.json() as any) }, 201);
        }
        // API Keys
        else if (path === '/api/admin/api-keys' && method === 'GET') {
          response = utils.successResponse({ api_keys: await admin.listApiKeys(context) });
        }
        else if (path === '/api/admin/api-keys' && method === 'POST') {
          const result = await admin.createApiKey(context, await request.json() as any);
          response = utils.successResponse({ api_key: result.apiKey, raw_key: result.rawKey }, 201);
        }
        else if (path.match(/^\/api\/admin\/api-keys\/[^/]+$/) && method === 'DELETE') {
          await admin.revokeApiKey(context, path.split('/').pop()!);
          response = utils.successResponse({ message: 'API key revoked' });
        }
        // Audit logs
        else if (path === '/api/admin/audit-logs' && method === 'GET') {
          const p = Object.fromEntries(url.searchParams);
          response = utils.successResponse(await admin.getAuditLogs(context, {
            page: parseInt(p.page || '1'), limit: parseInt(p.limit || '50'),
            user_id: p.user_id ? parseInt(p.user_id) : undefined,
            action: p.action, from: p.from, to: p.to,
          }));
        }
        // Stats
        else if (path === '/api/admin/stats' && method === 'GET') {
          response = utils.successResponse(await admin.getStats(context));
        }
        else {
          response = utils.errorResponse('Endpoint not found', 'NOT_FOUND', 404);
        }
      }
      // === API KEY AUTH ===
      else if (path === '/api/protected' && method === 'GET') {
        const context = await middleware.authenticateApiKey(request);
        response = utils.successResponse({ message: 'API key valid', tenant: context.tenant });
      }
      // === HEALTH ===
      else if (path === '/health') {
        response = new Response(JSON.stringify({ status: 'ok', timestamp: new Date().toISOString() }), {
          headers: { 'Content-Type': 'application/json' },
        });
      }
      else {
        response = utils.errorResponse('Endpoint not found', 'NOT_FOUND', 404);
      }

      // Apply headers
      response = middleware.addCorsHeaders(response, request);
      response = middleware.addSecurityHeaders(response);
      return response;

    } catch (error: any) {
      const errResp = middleware.handleError(error, request);
      return middleware.addCorsHeaders(errResp, request);
    }
  },
};
