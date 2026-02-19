import { useEffect, useMemo, useState } from "react";

import PageShell from "./PageShell";
import { apiRequest } from "../utils/api";
import type { Scope } from "../types";

type Message = { text: string; variant: "info" | "success" | "error" };

type ScopeForm = {
  key: string;
  description: string;
  isExternal: boolean;
  externalEndpoint: string;
  externalMethod: string;
  authType: string;
  authSecretEnv: string;
};

const emptyScopeForm: ScopeForm = {
  key: "",
  description: "",
  isExternal: false,
  externalEndpoint: "",
  externalMethod: "",
  authType: "",
  authSecretEnv: "",
};

const DEFAULT_SCOPES: Scope[] = [
  {
    id: "sso-profile",
    key: "sso.profile",
    description: "SSO server user profile information (email, username, avatar)",
    is_external: false,
    created_at: "",
    updated_at: "",
  },
  {
    id: "openid",
    key: "openid",
    description: "OpenID Connect standard scope for user identity",
    is_external: false,
    created_at: "",
    updated_at: "",
  },
  {
    id: "email",
    key: "email",
    description: "Access to user email address and email verification status",
    is_external: false,
    created_at: "",
    updated_at: "",
  },
  {
    id: "profile",
    key: "profile",
    description: "Access to standard user profile information",
    is_external: false,
    created_at: "",
    updated_at: "",
  },
  {
    id: "oauth-register",
    key: "oauth:register",
    description: "Permission to register OAuth applications",
    is_external: false,
    created_at: "",
    updated_at: "",
  },
];

export default function ScopesPage() {
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState<Message>({ text: "", variant: "info" });
  const [form, setForm] = useState<ScopeForm>(emptyScopeForm);
  const [showCreateForm, setShowCreateForm] = useState(false);

  const messageClasses = useMemo(
    () => ({
      info: "text-slate-600 dark:text-slate-400",
      success: "text-emerald-600 dark:text-emerald-400",
      error: "text-rose-600 dark:text-rose-400",
    }),
    []
  );

  const loadScopes = async () => {
    setIsLoading(true);
    try {
      const data = await apiRequest<Scope[]>("/admin/scopes");
      setScopes(data);
      setMessage({ text: "", variant: "info" });
    } catch (error) {
      // Fallback to default scopes if API not ready
      console.warn("Failed to load scopes from API, using defaults");
      setScopes(DEFAULT_SCOPES);
      setMessage({ text: "", variant: "info" });
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadScopes();
  }, []);

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!form.key.trim()) {
      setMessage({ text: "Scope key is required", variant: "error" });
      return;
    }

    setMessage({ text: "Creating scope...", variant: "info" });
    try {
      const payload = {
        scope: form.key.trim(),
        description: form.description.trim(),
        is_external: form.isExternal,
        external_endpoint: form.isExternal ? form.externalEndpoint : undefined,
        external_method: form.isExternal ? form.externalMethod : undefined,
        auth_type: form.authType || undefined,
        auth_secret_env: form.authSecretEnv || undefined,
        json_schema: {},
        data: "",
      };
      await apiRequest<Scope>("/admin/scopes", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setForm(emptyScopeForm);
      setShowCreateForm(false);
      setMessage({ text: "Scope created successfully", variant: "success" });
      await loadScopes();
    } catch (error) {
      setMessage({ text: error instanceof Error ? error.message : "Failed to create scope", variant: "error" });
    }
  };

  const deleteScope = async (scope: Scope) => {
    if (!confirm(`Are you sure you want to delete scope "${scope.key}"?`)) {
      return;
    }

    setMessage({ text: "Deleting scope...", variant: "info" });
    try {
      await apiRequest(`/admin/scopes/${scope.id}`, { method: "DELETE" });
      setMessage({ text: "Scope deleted successfully", variant: "success" });
      await loadScopes();
    } catch (error) {
      setMessage({ text: error instanceof Error ? error.message : "Failed to delete scope", variant: "error" });
    }
  };

  return (
    <PageShell
      title="OAuth Scopes"
      subtitle="Manage OAuth scopes and permissions for client applications."
      actions={
        <button
          type="button"
          onClick={loadScopes}
          className="rounded-2xl border border-amber-200 px-4 py-2 text-sm font-semibold text-amber-700 transition hover:border-amber-300 hover:bg-amber-50 dark:border-amber-700/60 dark:text-amber-300 dark:hover:bg-amber-600/20"
        >
          Refresh
        </button>
      }
    >
      <section className="grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
        <div className="rounded-3xl border border-amber-100 bg-white/95 p-6 shadow-lg shadow-amber-100/40 dark:border-slate-800 dark:bg-slate-900/70">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">Scope Library</h2>
            {isLoading ? <span className="text-xs text-slate-500">Loading...</span> : null}
          </div>
          <div className="mt-4 space-y-4">
            {scopes.length === 0 && !isLoading ? (
              <p className="text-sm text-slate-500 dark:text-slate-400">No scopes available yet.</p>
            ) : null}
            {scopes.map((scope) => (
              <div
                key={scope.id}
                className="rounded-2xl border border-amber-100/80 bg-amber-50/50 p-4 text-sm text-slate-700 dark:border-slate-800 dark:bg-slate-800/60 dark:text-slate-200"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="flex-1">
                    <p className="text-xs font-semibold uppercase tracking-[0.2em] text-amber-700">{scope.key}</p>
                    {scope.description && (
                      <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">{scope.description}</p>
                    )}
                    {scope.is_external && (
                      <p className="mt-2 text-xs text-amber-600 dark:text-amber-400">
                        External: {scope.external_endpoint}
                      </p>
                    )}
                  </div>
                  <button
                    type="button"
                    onClick={() => deleteScope(scope)}
                    className="rounded-full border border-rose-200 px-3 py-1 text-xs font-semibold text-rose-600 transition hover:bg-rose-50 dark:border-rose-500/40 dark:text-rose-300 dark:hover:bg-rose-600/10"
                  >
                    Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-3xl border border-amber-100 bg-white/95 p-6 dark:border-slate-800 dark:bg-slate-900/70">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">Create Scope</h2>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Define a new OAuth scope for your applications.
          </p>

          {showCreateForm ? (
            <form className="mt-5 space-y-4" onSubmit={handleSubmit}>
              <label className="block">
                <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700">Scope Key</span>
                <input
                  type="text"
                  required
                  value={form.key}
                  onChange={(event) => setForm({ ...form, key: event.target.value })}
                  placeholder="e.g., sso.profile"
                  className="mt-2 w-full rounded-2xl border border-amber-100 bg-white px-4 py-3 text-sm text-slate-900 shadow-sm focus:border-amber-400 focus:outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
                />
              </label>
              <label className="block">
                <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700">Description</span>
                <input
                  type="text"
                  value={form.description}
                  onChange={(event) => setForm({ ...form, description: event.target.value })}
                  placeholder="What does this scope provide?"
                  className="mt-2 w-full rounded-2xl border border-amber-100 bg-white px-4 py-3 text-sm text-slate-900 shadow-sm focus:border-amber-400 focus:outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
                />
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={form.isExternal}
                  onChange={(event) => setForm({ ...form, isExternal: event.target.checked })}
                  className="h-4 w-4 rounded border-amber-200"
                />
                <span className="text-sm font-medium text-slate-700 dark:text-slate-300">External Scope</span>
              </label>
              {form.isExternal && (
                <>
                  <label className="block">
                    <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700">
                      External Endpoint
                    </span>
                    <input
                      type="url"
                      value={form.externalEndpoint}
                      onChange={(event) => setForm({ ...form, externalEndpoint: event.target.value })}
                      placeholder="https://api.example.com/user"
                      className="mt-2 w-full rounded-2xl border border-amber-100 bg-white px-4 py-3 text-sm text-slate-900 shadow-sm focus:border-amber-400 focus:outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
                    />
                  </label>
                  <label className="block">
                    <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700">
                      HTTP Method
                    </span>
                    <input
                      type="text"
                      value={form.externalMethod}
                      onChange={(event) => setForm({ ...form, externalMethod: event.target.value })}
                      placeholder="GET"
                      className="mt-2 w-full rounded-2xl border border-amber-100 bg-white px-4 py-3 text-sm text-slate-900 shadow-sm focus:border-amber-400 focus:outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
                    />
                  </label>
                </>
              )}
              <div className="flex gap-2">
                <button
                  type="submit"
                  className="flex-1 rounded-2xl bg-slate-900 px-4 py-3 text-sm font-semibold text-white transition hover:-translate-y-0.5 dark:bg-amber-600"
                >
                  Create
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setShowCreateForm(false);
                    setForm(emptyScopeForm);
                    setMessage({ text: "", variant: "info" });
                  }}
                  className="flex-1 rounded-2xl border border-amber-200 px-4 py-3 text-sm font-semibold text-amber-700 transition hover:bg-amber-50 dark:border-amber-700/60 dark:text-amber-300 dark:hover:bg-amber-600/20"
                >
                  Cancel
                </button>
              </div>
            </form>
          ) : (
            <button
              type="button"
              onClick={() => setShowCreateForm(true)}
              className="mt-6 w-full rounded-2xl bg-slate-900 px-4 py-3 text-sm font-semibold text-white transition hover:-translate-y-0.5 dark:bg-amber-600"
            >
              New Scope
            </button>
          )}

          {message.text ? (
            <p className={`mt-4 text-sm ${messageClasses[message.variant]}`}>{message.text}</p>
          ) : null}
        </div>
      </section>
    </PageShell>
  );
}
