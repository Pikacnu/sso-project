import { useEffect, useMemo, useState } from "react";

import PageShell from "./PageShell";
import { apiRequest } from "../utils/api";
import type { Role } from "../types";

type Message = { text: string; variant: "info" | "success" | "error" };

type RoleForm = {
  name: string;
  description: string;
};

const emptyForm: RoleForm = {
  name: "",
  description: "",
};

export default function RolesPage() {
  const [roles, setRoles] = useState<Role[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState<Message>({ text: "", variant: "info" });
  const [form, setForm] = useState<RoleForm>(emptyForm);

  const messageClasses = useMemo(
    () => ({
      info: "text-slate-600 dark:text-slate-400",
      success: "text-emerald-600 dark:text-emerald-400",
      error: "text-rose-600 dark:text-rose-400",
    }),
    []
  );

  const loadRoles = async () => {
    setIsLoading(true);
    try {
      const data = await apiRequest<Role[]>("/roles");
      setRoles(data);
      setMessage({ text: "", variant: "info" });
    } catch (error) {
      setMessage({ text: error instanceof Error ? error.message : "Failed to load roles", variant: "error" });
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadRoles();
  }, []);

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setMessage({ text: "Creating role...", variant: "info" });
    try {
      const payload = {
        name: form.name,
        description: form.description || undefined,
      };
      await apiRequest<Role>("/roles", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setForm(emptyForm);
      setMessage({ text: "Role created.", variant: "success" });
      await loadRoles();
    } catch (error) {
      setMessage({ text: error instanceof Error ? error.message : "Failed to create role", variant: "error" });
    }
  };

  const deleteRole = async (role: Role) => {
    setMessage({ text: "Deleting role...", variant: "info" });
    try {
      await apiRequest(`/roles/${role.id}`, { method: "DELETE" });
      setMessage({ text: "Role deleted.", variant: "success" });
      await loadRoles();
    } catch (error) {
      setMessage({ text: error instanceof Error ? error.message : "Failed to delete role", variant: "error" });
    }
  };

  return (
    <PageShell
      title="Roles"
      subtitle="Define role groups and keep authorization assignments organized."
      actions={
        <button
          type="button"
          onClick={loadRoles}
          className="rounded-2xl border border-amber-200 px-4 py-2 text-sm font-semibold text-amber-700 transition hover:border-amber-300 hover:bg-amber-50 dark:border-amber-700/60 dark:text-amber-300 dark:hover:bg-amber-600/20"
        >
          Refresh
        </button>
      }
    >
      <section className="grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
        <div className="rounded-3xl border border-amber-100 bg-white/95 p-6 dark:border-slate-800 dark:bg-slate-900/70">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">Role List</h2>
            {isLoading ? <span className="text-xs text-slate-500">Loading...</span> : null}
          </div>
          <div className="mt-4 space-y-4">
            {roles.length === 0 && !isLoading ? (
              <p className="text-sm text-slate-500 dark:text-slate-400">No roles yet.</p>
            ) : null}
            {roles.map((role) => (
              <div
                key={role.id}
                className="rounded-2xl border border-amber-100/80 bg-amber-50/50 p-4 text-sm text-slate-700 dark:border-slate-800 dark:bg-slate-800/60 dark:text-slate-200"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-[0.2em] text-amber-700">{role.name}</p>
                    <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">{role.description || "No description"}</p>
                  </div>
                  <button
                    type="button"
                    onClick={() => deleteRole(role)}
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
          <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">Create Role</h2>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">Define a reusable authorization role.</p>
          <form className="mt-5 space-y-4" onSubmit={handleSubmit}>
            <label className="block">
              <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700">Role Name</span>
              <input
                value={form.name}
                onChange={(event) => setForm({ ...form, name: event.target.value })}
                required
                className="mt-2 w-full rounded-2xl border border-amber-100 bg-white px-4 py-3 text-sm text-slate-900 focus:border-amber-400 focus:outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
              />
            </label>
            <label className="block">
              <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700">Description</span>
              <textarea
                value={form.description}
                onChange={(event) => setForm({ ...form, description: event.target.value })}
                placeholder="Optional role description"
                className="mt-2 min-h-24 w-full rounded-2xl border border-amber-100 bg-white px-4 py-3 text-sm text-slate-900 focus:border-amber-400 focus:outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
              />
            </label>
            <button
              type="submit"
              className="w-full rounded-2xl bg-slate-900 px-4 py-3 text-sm font-semibold text-white transition hover:-translate-y-0.5 dark:bg-amber-600"
            >
              Create Role
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
