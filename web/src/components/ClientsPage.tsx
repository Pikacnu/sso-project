import { useEffect, useMemo, useState } from "react";

import PageShell from "./PageShell";
import { apiRequest, APIError } from "../utils/api";
import type { Client, ClientWithSecret } from "../types";

type Message = { text: string; variant: "info" | "success" | "error" };

type ClientForm = {
  app_name: string;
  domain: string;
  redirect_uris: string;
  allowed_scopes: string;
  owner_id: string;
  logo_url: string;
  is_active: boolean;
};

const emptyForm: ClientForm = {
  app_name: "",
  domain: "",
  redirect_uris: "",
  allowed_scopes: "openid,profile,email",
  owner_id: "",
  logo_url: "",
  is_active: true,
};

export default function ClientsPage() {
  const [clients, setClients] = useState<Client[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState<Message>({ text: "", variant: "info" });
  const [form, setForm] = useState<ClientForm>(emptyForm);
  const [rotatedSecret, setRotatedSecret] = useState<string | null>(null);

  const messageClasses = useMemo(
    () => ({
      info: "text-slate-600 dark:text-slate-400",
      success: "text-emerald-600 dark:text-emerald-400",
      error: "text-rose-600 dark:text-rose-400",
    }),
    []
  );

  const loadClients = async () => {
    setIsLoading(true);
    try {
      const data = await apiRequest<Client[]>("/clients");
      setClients(data);
      setMessage({ text: "", variant: "info" });
    } catch (error) {
      setMessage({ text: error instanceof Error ? error.message : "Failed to load clients", variant: "error" });
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadClients();
  }, []);

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setMessage({ text: "Creating client...", variant: "info" });
    try {
      const payload = {
        app_name: form.app_name,
        domain: form.domain,
        redirect_uris: form.redirect_uris,
        allowed_scopes: form.allowed_scopes,
        owner_id: form.owner_id,
        logo_url: form.logo_url || undefined,
        is_active: form.is_active,
      };
      await apiRequest<ClientWithSecret>("/clients", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setMessage({ text: "Client created.", variant: "success" });
      setForm(emptyForm);
      await loadClients();
    } catch (error) {
      setMessage({ text: error instanceof Error ? error.message : "Failed to create client", variant: "error" });
    }
  };

  const toggleClient = async (client: Client) => {
    const endpoint = client.is_active ? `/clients/${client.id}/disable` : `/clients/${client.id}/enable`;
    setMessage({ text: "Updating client status...", variant: "info" });
    try {
      await apiRequest(endpoint, { method: "POST" });
      await loadClients();
      setMessage({ text: "Client status updated.", variant: "success" });
    } catch (error) {
      setMessage({ text: error instanceof Error ? error.message : "Failed to update client", variant: "error" });
    }
  };

  const rotateSecret = async (client: Client) => {
    setMessage({ text: "Rotating secret...", variant: "info" });
    try {
      const result = await apiRequest<ClientWithSecret>(`/clients/${client.id}/rotate-secret`, { method: "POST" });
      setRotatedSecret(result.client_secret);
      setMessage({ text: "Secret rotated. Store it somewhere safe.", variant: "success" });
    } catch (error) {
      const text = error instanceof APIError && error.errorDescription ? error.errorDescription : "Failed to rotate secret";
      setMessage({ text, variant: "error" });
    }
  };

  return (
    <PageShell
      title="OAuth Clients"
      subtitle="Create and manage OAuth clients, secrets, and redirect URIs for your applications."
      actions={
        <button
          type="button"
          onClick={loadClients}
          className="rounded-2xl border border-amber-200 px-4 py-2 text-sm font-semibold text-amber-700 transition hover:border-amber-300 hover:bg-amber-50 dark:border-amber-700/60 dark:text-amber-300 dark:hover:bg-amber-600/20"
        >
          Refresh
        </button>
      }
    >
      <section className="grid gap-6 lg:grid-cols-[1.1fr_0.9fr] grow">
        <div className="rounded-3xl border border-amber-100 bg-white/95 p-6 dark:border-slate-800 dark:bg-slate-900/70">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">Active Clients</h2>
            {isLoading ? <span className="text-xs text-slate-500">Loading...</span> : null}
          </div>
          <div className="mt-4 space-y-4">
            {clients.length === 0 && !isLoading ? (
              <p className="text-sm text-slate-500 dark:text-slate-400">No clients yet. Create the first one to start issuing tokens.</p>
            ) : null}
            {clients.map((client) => (
              <div
                key={client.id}
                className="rounded-2xl border border-amber-100/80 bg-amber-50/50 p-4 text-sm text-slate-700 dark:border-slate-800 dark:bg-slate-800/60 dark:text-slate-200"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-[0.2em] text-amber-700">{client.app_name}</p>
                    <p className="mt-1 text-sm font-semibold text-slate-900 dark:text-slate-100">{client.domain}</p>
                    <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">Redirect URIs: {client.redirect_uris}</p>
                    <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">Scopes: {client.allowed_scopes}</p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={() => toggleClient(client)}
                      className="rounded-full border border-amber-200 px-3 py-1 text-xs font-semibold text-amber-700 transition hover:bg-amber-100 dark:border-amber-700/60 dark:text-amber-300 dark:hover:bg-amber-600/20"
                    >
                      {client.is_active ? "Disable" : "Enable"}
                    </button>
                    <button
                      type="button"
                      onClick={() => rotateSecret(client)}
                      className="rounded-full border border-slate-200 px-3 py-1 text-xs font-semibold text-slate-700 transition hover:bg-slate-100 dark:border-slate-700 dark:text-slate-200 dark:hover:bg-slate-700"
                    >
                      Rotate Secret
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
          {rotatedSecret ? (
            <div className="mt-5 rounded-2xl border border-emerald-200 bg-emerald-50/70 p-4 text-xs text-emerald-700 dark:border-emerald-700/50 dark:bg-emerald-600/10 dark:text-emerald-300">
              New client secret: <span className="break-all font-semibold">{rotatedSecret}</span>
            </div>
          ) : null}
        </div>

        <div className="rounded-3xl border border-amber-100 bg-white/95 p-6 dark:border-slate-800 dark:bg-slate-900/70">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">Create a Client</h2>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">Register a new OAuth client application.</p>
          <form className="mt-5 space-y-4" onSubmit={handleSubmit}>
            <label className="block">
              <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700">App Name</span>
              <input
                value={form.app_name}
                onChange={(event) => setForm({ ...form, app_name: event.target.value })}
                required
                className="mt-2 w-full rounded-2xl border border-amber-100 bg-white px-4 py-3 text-sm text-slate-900 focus:border-amber-400 focus:outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
              />
            </label>
            <label className="block">
              <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700">Domain</span>
              <input
                value={form.domain}
                onChange={(event) => setForm({ ...form, domain: event.target.value })}
                required
                placeholder="app.example.com"
                className="mt-2 w-full rounded-2xl border border-amber-100 bg-white px-4 py-3 text-sm text-slate-900 focus:border-amber-400 focus:outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
              />
            </label>
            <label className="block">
              <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700">Redirect URIs</span>
              <textarea
                value={form.redirect_uris}
                onChange={(event) => setForm({ ...form, redirect_uris: event.target.value })}
                required
                placeholder="https://app.example.com/callback"
                className="mt-2 min-h-24 w-full rounded-2xl border border-amber-100 bg-white px-4 py-3 text-sm text-slate-900 focus:border-amber-400 focus:outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
              />
            </label>
            <label className="block">
              <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700">Allowed Scopes</span>
              <input
                value={form.allowed_scopes}
                onChange={(event) => setForm({ ...form, allowed_scopes: event.target.value })}
                required
                className="mt-2 w-full rounded-2xl border border-amber-100 bg-white px-4 py-3 text-sm text-slate-900 focus:border-amber-400 focus:outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
              />
            </label>
            <label className="block">
              <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700">Owner ID</span>
              <input
                value={form.owner_id}
                onChange={(event) => setForm({ ...form, owner_id: event.target.value })}
                required
                className="mt-2 w-full rounded-2xl border border-amber-100 bg-white px-4 py-3 text-sm text-slate-900 focus:border-amber-400 focus:outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
              />
            </label>
            <label className="block">
              <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700">Logo URL</span>
              <input
                value={form.logo_url}
                onChange={(event) => setForm({ ...form, logo_url: event.target.value })}
                placeholder="https://cdn.example.com/logo.svg"
                className="mt-2 w-full rounded-2xl border border-amber-100 bg-white px-4 py-3 text-sm text-slate-900 focus:border-amber-400 focus:outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
              />
            </label>
            <label className="flex items-center gap-3 text-sm text-slate-700 dark:text-slate-200">
              <input
                type="checkbox"
                checked={form.is_active}
                onChange={(event) => setForm({ ...form, is_active: event.target.checked })}
                className="h-4 w-4 rounded border-amber-200 text-amber-600"
              />
              Active on creation
            </label>
            <button
              type="submit"
              className="w-full rounded-2xl bg-slate-900 px-4 py-3 text-sm font-semibold text-white transition hover:-translate-y-0.5 dark:bg-amber-600"
            >
              Create Client
            </button>
          </form>
          {message.text ? (
            <p className={`mt-4 text-sm ${messageClasses[message.variant]}`}>{message.text}</p>
          ) : null}
        </div>
      </section>
    </PageShell>
  );
}
