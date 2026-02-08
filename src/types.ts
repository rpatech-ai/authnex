// Date: 2025-02-07
// Author: Alok
// File: src/types.ts
// Purpose: TypeScript interfaces for auth platform

// Core entities
export interface User {
  id: number;
  email: string;
  password_hash: string;
  status: 'active' | 'pending' | 'locked' | 'deleted';
  email_verified: boolean;
  email_verified_at?: string;
  locked_reason?: string;
  locked_at?: string;
  locked_by?: number;
  failed_attempts: number;
  last_failed_at?: string;
  force_password_reset?: boolean;
  created_at: string;
  updated_at: string;
  deleted_at?: string;
  metadata: Record<string, any>;
}

export interface Tenant {
  id: number;
  slug: string;
  name: string;
  status: 'active' | 'suspended' | 'trial';
  settings: TenantSettings;
  plan: string;
  created_at: string;
  updated_at: string;
  suspended_at?: string;
  trial_ends_at?: string;
  metadata: Record<string, any>;
}

export interface TenantSettings {
  branding?: { logo?: string; primaryColor?: string; name?: string };
  features?: string[];
  limits?: { maxUsers?: number; maxApiCalls?: number };
  security?: {
    passwordPolicy?: PasswordPolicy;
    mfaRequired?: boolean;
    sessionTimeout?: number;
  };
  webhooks?: { url: string; events: string[]; secret?: string }[];
}

export interface PasswordPolicy {
  minLength?: number;
  requireUppercase?: boolean;
  requireLowercase?: boolean;
  requireNumbers?: boolean;
  requireSpecialChars?: boolean;
  maxAge?: number;
}

export interface Role {
  id: number;
  tenant_id: number;
  name: string;
  permissions: string[];
  is_system: boolean;
  created_at: string;
}

export interface UserTenant {
  user_id: number;
  tenant_id: number;
  joined_at: string;
  invited_by?: number;
  invite_accepted_at?: string;
  is_primary: boolean;
  settings: Record<string, any>;
}

export interface UserRole {
  user_id: number;
  tenant_id: number;
  role_id: number;
  granted_at: string;
  granted_by?: number;
  expires_at?: string;
}

// Token types
export interface RefreshToken {
  id: string;
  user_id: number;
  tenant_id?: number;
  token_hash: string;
  family_id: string;
  expires_at: string;
  last_used_at?: string;
  ip_address?: string;
  user_agent?: string;
  created_at: string;
  revoked_at?: string;
  revoked_reason?: string;
}

export interface ApiKey {
  id: string;
  tenant_id: number;
  name: string;
  key_hash: string;
  key_prefix: string;
  permissions: string[];
  last_used_at?: string;
  expires_at?: string;
  created_at: string;
  created_by: number;
  revoked_at?: string;
  ip_whitelist?: string[];
  rate_limit: number;
}

export interface VerificationToken {
  id: string;
  user_id: number;
  type: 'email' | 'password' | 'invite';
  token_hash: string;
  expires_at: string;
  used_at?: string;
  created_at: string;
  metadata: Record<string, any>;
}

export interface Session {
  id: string;
  user_id: number;
  tenant_id?: number;
  token_hash: string;
  token?: string;
  ip_address?: string;
  user_agent?: string;
  last_activity: string;
  expires_at: string;
  created_at: string;
}

export interface AuditLog {
  id: number;
  tenant_id?: number;
  user_id?: number;
  action: string;
  resource_type?: string;
  resource_id?: string;
  changes?: Record<string, any>;
  ip_address?: string;
  user_agent?: string;
  success: boolean;
  error_message?: string;
  created_at: string;
}

// JWT payloads
export interface JWTPayload {
  sub: string;
  email: string;
  tid?: string;
  roles?: string[];
  permissions?: string[];
  iat: number;
  exp: number;
  jti?: string;
}

export interface RefreshTokenPayload {
  sub: string;
  tid?: string;
  fid: string;
  iat: number;
  exp: number;
}

// API request/response types
export interface LoginRequest {
  email: string;
  password: string;
  tenant_slug?: string;
  remember_me?: boolean;
}

export interface LoginResponse {
  success: boolean;
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  user: Partial<User>;
  tenant?: Partial<Tenant>;
  force_password_reset?: boolean;
}

export interface RegisterRequest {
  email: string;
  password: string;
  tenant_slug?: string;
  metadata?: Record<string, any>;
}

export interface ResetPasswordRequest {
  token: string;
  password: string;
}

export interface VerifyEmailRequest {
  token: string;
}

export interface SetupRequest {
  email: string;
  password: string;
  tenant_name?: string;
  tenant_slug?: string;
}

export interface ApiKeyCreateRequest {
  name: string;
  permissions?: string[];
  expires_in_days?: number;
  ip_whitelist?: string[];
  rate_limit?: number;
}

// Webhook event dispatched on key actions
export interface WebhookEvent {
  event: string;
  tenant_id?: number;
  data: Record<string, any>;
  timestamp: string;
}

// GDPR data export
export interface GDPRExportData {
  user: Partial<User>;
  tenants: Partial<Tenant>[];
  roles: { tenant: string; roles: string[] }[];
  sessions: Partial<Session>[];
  audit_logs: Partial<AuditLog>[];
}

// Middleware context — token field replaces immutable header hack
export interface AuthContext {
  user?: User;
  tenant?: Tenant;
  roles?: Role[];
  permissions?: string[];
  session?: Session;
  token?: string;
}

// Worker environment bindings
export interface Env {
  DB: D1Database;
  CACHE: KVNamespace;
  SESSIONS: KVNamespace;
  BLACKLIST: KVNamespace;
  JWT_PRIVATE_KEY: string;
  JWT_PUBLIC_KEY: string;
  SMTP_API_KEY: string;
  SMTP_FROM: string;
  ADMIN_INITIAL_PASSWORD?: string;
  APP_URL: string;
  ENVIRONMENT: 'development' | 'staging' | 'production';
}

// Error types
export interface ApiError {
  code: string;
  message: string;
  details?: any;
  timestamp: string;
}

export type ApiResponse<T = any> =
  | { success: true; data: T }
  | { success: false; error: ApiError };

// Pagination
export interface PaginationParams {
  page?: number;
  limit?: number;
  sort?: string;
  order?: 'asc' | 'desc';
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  pages: number;
  limit: number;
}
