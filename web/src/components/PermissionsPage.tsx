import { useEffect, useMemo, useState } from "react";

import PageShell from "./PageShell";
import { apiRequest } from "../utils/api";
import type { Permission } from "../types";

type Message = { text: string; variant: "info" | "success" | "error" };

type PermissionForm = {
  key: string;
  description: string;
};

const emptyForm: PermissionForm = {
  key: "",
  description: ""
};

export default function PermissionsPage() {
  const [permissions, setPermissions] = useState<Permission[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState<Message>({ text: "", variant: "info" });
  const [form, setForm] = useState<PermissionForm>(emptyForm);

  const messageClasses = useMemo(
    () => ({
      info: "text-slate-600 dark:text-slate-400",
      success: "text-emerald-600 dark:text-emerald-400",
      error: "text-rose-600 dark:text-rose-400",
    }),
    []
  );

  const loadPermissions = async () => {
    setIsLoading(true);
    try {
      const data = await apiRequest<Permission[]>("/permissions");
      setPermissions(data);
      setMessage({ text: "", variant: "info" });
    } catch (error) {
      setMessage({ text: error instanceof Error ? error.message : "Failed to load permissions", variant: "error" });
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadPermissions();
  }, []);

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setMessage({ text: "Creating permission...", variant: "info" });
    try {
      const payload = {
        key: form.key,
        description: form.description || undefined,
      };
      await apiRequest<Permission>("/permissions", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setForm(emptyForm);
      setMessage({ text: "Permission created.", variant: "success" });
      await loadPermissions();
    } catch (error) {
      setMessage({ text: error instanceof Error ? error.message : "Failed to create permission", variant: "error" });
    }
  };

  const deletePermission = async (permission: Permission) => {
    setMessage({ text: "Deleting permission...", variant: "info" });
    try {
      await apiRequest(`/permissions/${permission.id}`, { method: "DELETE" });
      setMessage({ text: "Permission deleted.", variant: "success" });
      await loadPermissions();
    } catch (error) {
      setMessage({ text: error instanceof Error ? error.message : "Failed to delete permission", variant: "error" });
    }
  };

  return (
    <PageShell
      title="Permissions"
      subtitle="Define fine-grained permissions that map to protected resources."
      actions={
        <button
          type="button"
          onClick={loadPermissions}
          className="rounded-2xl border border-amber-200 px-4 py-2 text-sm font-semibold text-amber-700 transition hover:border-amber-300 hover:bg-amber-50 dark:border-amber-700/60 dark:text-amber-300 dark:hover:bg-amber-600/20"
        >
          Refresh
        </button>
      }
    >
      <section className="grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
        <div className="rounded-3xl border border-amber-100 bg-white/95 p-6 dark:border-slate-800 dark:bg-slate-900/70">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">Permission Library</h2>
            {isLoading ? <span className="text-xs text-slate-500">Loading...</span> : null}
          </div>
          <div className="mt-4 space-y-4">
            {permissions.length === 0 && !isLoading ? (
              <p className="text-sm text-slate-500 dark:text-slate-400">No permissions created yet.</p>
            ) : null}
            {permissions.map((permission) => (
              <div
                key={permission.id}
                className="rounded-2xl border border-amber-100/80 bg-amber-50/50 p-4 text-sm text-slate-700 dark:border-slate-800 dark:bg-slate-800/60 dark:text-slate-200"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-[0.2em] text-amber-700">{(permission as any).key || permission.id}</p>
                    <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                      {permission.description || "No description"}
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => deletePermission(permission)}
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
          <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">Create Permission</h2>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">Add a new permission scope.</p>
          <form className="mt-5 space-y-4" onSubmit={handleSubmit}>
            <label className="block">
              <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700">Permission Key</span>
              <input
                value={form.key}
                onChange={(event) => setForm({ ...form, key: event.target.value })}
                required
                className="mt-2 w-full rounded-2xl border border-amber-100 bg-white px-4 py-3 text-sm text-slate-900 focus:border-amber-400 focus:outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
              />
            </label>
            <label className="block">
              <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700">Description</span>
              <textarea
                value={form.description}
                onChange={(event) => setForm({ ...form, description: event.target.value })}
                placeholder="Optional permission description"
                className="mt-2 min-h-24 w-full rounded-2xl border border-amber-100 bg-white px-4 py-3 text-sm text-slate-900 focus:border-amber-400 focus:outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
              />
            </label>
            <button
              type="submit"
              className="w-full rounded-2xl bg-slate-900 px-4 py-3 text-sm font-semibold text-white transition hover:-translate-y-0.5 dark:bg-amber-600"
            >
              Create Permission
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
