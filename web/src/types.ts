export interface Client {
  id: string;
  app_name: string;
  domain: string;
  redirect_uris: string;
  allowed_scopes: string;
  owner_id: string;
  logo_url?: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface ClientWithSecret extends Client {
  client_secret: string;
}

export interface User {
  id: string;
  username: string;
  email: string;
  avatar?: string;
  email_verified: boolean;
  created_at: string;
  updated_at: string;
}

export interface Role {
  id: string;
  name: string;
  description?: string;
  created_at: string;
  updated_at: string;
}

export interface Permission {
  id: string;
  key: string;
  description?: string;
  created_at: string;
  updated_at: string;
}

export interface Scope {
  id: string;
  key: string;
  description?: string;
  is_external: boolean;
  external_endpoint?: string;
  external_method?: string;
  auth_type?: string;
  auth_secret_env?: string;
  json_schema?: string;
  data?: string;
  created_at: string;
  updated_at: string;
}
