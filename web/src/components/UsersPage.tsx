import { useEffect, useMemo, useState } from "react";

import PageShell from "./PageShell";
import { apiRequest } from "../utils/api";
import type { User } from "../types";

type Message = { text: string; variant: "info" | "success" | "error" };

type UserForm = {
  username: string;
  email: string;
  password: string;
};

const emptyForm: UserForm = {
  username: "",
  email: "",
  password: "",
};

export default function UsersPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState<Message>({ text: "", variant: "info" });
  const [form, setForm] = useState<UserForm>(emptyForm);

  const messageClasses = useMemo(
    () => ({
      info: "text-slate-600 dark:text-slate-400",
      success: "text-emerald-600 dark:text-emerald-400",
      error: "text-rose-600 dark:text-rose-400",
    }),
    []
  );

  const loadUsers = async () => {
    setIsLoading(true);
    try {
      const data = await apiRequest<User[]>("/users");
      setUsers(data);
      setMessage({ text: "", variant: "info" });
    } catch (error) {
      setMessage({ text: error instanceof Error ? error.message : "Failed to load users", variant: "error" });
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadUsers();
  }, []);

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setMessage({ text: "Creating user...", variant: "info" });
    try {
      const payload = {
        username: form.username,
        email: form.email,
        password: form.password || undefined,
      };
      await apiRequest<User>("/users", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setForm(emptyForm);
      setMessage({ text: "User created.", variant: "success" });
      await loadUsers();
    } catch (error) {
      setMessage({ text: error instanceof Error ? error.message : "Failed to create user", variant: "error" });
    }
  };

  const deleteUser = async (user: User) => {
    setMessage({ text: "Deleting user...", variant: "info" });
    try {
      await apiRequest(`/users/${user.id}`, { method: "DELETE" });
      setMessage({ text: "User deleted.", variant: "success" });
      await loadUsers();
    } catch (error) {
      setMessage({ text: error instanceof Error ? error.message : "Failed to delete user", variant: "error" });
    }
  };

  return (
    <PageShell
      title="Users"
      subtitle="Manage registered users, verification status, and onboarding flows."
      actions={
        <button
          type="button"
          onClick={loadUsers}
          className="rounded-2xl border border-amber-200 px-4 py-2 text-sm font-semibold text-amber-700 transition hover:border-amber-300 hover:bg-amber-50 dark:border-amber-700/60 dark:text-amber-300 dark:hover:bg-amber-600/20"
        >
          Refresh
        </button>
      }
    >
      <section className="grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
        <div className="rounded-3xl border border-amber-100 bg-white/95 p-6  shadow-amber-100/40 dark:border-slate-800 dark:bg-slate-900/70">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">User Directory</h2>
            {isLoading ? <span className="text-xs text-slate-500">Loading...</span> : null}
          </div>
          <div className="mt-4 space-y-4">
            {users.length === 0 && !isLoading ? (
              <p className="text-sm text-slate-500 dark:text-slate-400">No users found yet.</p>
            ) : null}
            {users.map((user) => (
              <div
                key={user.id}
                className="rounded-2xl border border-amber-100/80 bg-amber-50/50 p-4 text-sm text-slate-700 dark:border-slate-800 dark:bg-slate-800/60 dark:text-slate-200"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-[0.2em] text-amber-700">{user.username || "Unnamed"}</p>
                    <p className="mt-1 text-sm font-semibold text-slate-900 dark:text-slate-100">{user.email}</p>
                    <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                      Verified: {user.email_verified ? "Yes" : "No"}
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => deleteUser(user)}
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
          <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">Create User</h2>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">Add a user for direct email authentication.</p>
          <form className="mt-5 space-y-4" onSubmit={handleSubmit}>
            <label className="block">
              <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700">Username</span>
              <input
                value={form.username}
                onChange={(event) => setForm({ ...form, username: event.target.value })}
                placeholder="Display name"
                className="mt-2 w-full rounded-2xl border border-amber-100 bg-white px-4 py-3 text-sm text-slate-900  focus:border-amber-400 focus:outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
              />
            </label>
            <label className="block">
              <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700">Email</span>
              <input
                type="email"
                required
                value={form.email}
                onChange={(event) => setForm({ ...form, email: event.target.value })}
                placeholder="you@example.com"
                className="mt-2 w-full rounded-2xl border border-amber-100 bg-white px-4 py-3 text-sm text-slate-900  focus:border-amber-400 focus:outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
              />
            </label>
            <label className="block">
              <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700">Password</span>
              <input
                type="password"
                value={form.password}
                onChange={(event) => setForm({ ...form, password: event.target.value })}
                placeholder="Optional password"
                className="mt-2 w-full rounded-2xl border border-amber-100 bg-white px-4 py-3 text-sm text-slate-900  focus:border-amber-400 focus:outline-none dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
              />
            </label>
            <button
              type="submit"
              className="w-full rounded-2xl bg-slate-900 px-4 py-3 text-sm font-semibold text-white transition hover:-translate-y-0.5 dark:bg-amber-600"
            >
              Create User
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
