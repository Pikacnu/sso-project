import { useEffect, useState } from "react";
import { apiRequest, APIError } from "../utils/api";

type AdminSetupForm = {
  email: string;
  username: string;
  password: string;
  confirmPassword: string;
};

const emptyForm: AdminSetupForm = {
  email: "",
  username: "",
  password: "",
  confirmPassword: "",
};

export default function AdminSetup() {
  const [form, setForm] = useState<AdminSetupForm>(emptyForm);
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState<{ text: string; variant: "info" | "success" | "error" } | null>(null);
  const [isComplete, setIsComplete] = useState(false);

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (!form.email || !form.username || !form.password) {
      setMessage({ text: "All fields are required", variant: "error" });
      return;
    }

    if (form.password.length < 8) {
      setMessage({ text: "Password must be at least 8 characters", variant: "error" });
      return;
    }

    if (form.password !== form.confirmPassword) {
      setMessage({ text: "Passwords do not match", variant: "error" });
      return;
    }

    setIsLoading(true);
    setMessage({ text: "Creating admin account...", variant: "info" });

    try {
      const response = await apiRequest<any>("/auth/admin/init", {
        method: "POST",
        body: JSON.stringify({
          email: form.email.trim(),
          username: form.username.trim(),
          password: form.password,
        }),
      });

      if (response.success) {
        setIsComplete(true);
        setMessage({
          text: "Admin account created successfully! Redirecting to login...",
          variant: "success",
        });
        setTimeout(() => {
          window.location.href = "/login";
        }, 2000);
      } else {
        setMessage({ text: response.message || "Failed to create admin account", variant: "error" });
      }
    } catch (error) {
      if (error instanceof APIError && error.statusCode === 409) {
        setMessage({ text: "Admin account already exists", variant: "error" });
      } else {
        setMessage({
          text: error instanceof Error ? error.message : "Failed to create admin account",
          variant: "error",
        });
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <main className="flex min-h-screen items-center justify-center bg-gradient-to-br from-amber-50 to-white px-4 dark:from-slate-950 dark:to-slate-900">
      <div className="w-full max-w-md">
        <div className="rounded-3xl border border-amber-200/70 bg-white/95 p-8 shadow-lg dark:border-slate-800 dark:bg-slate-900/80">
          <div className="mb-6 text-center">
            <div className="mx-auto mb-4 inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-amber-100 text-amber-700 dark:bg-amber-600/20 dark:text-amber-400">
              <span className="text-lg font-bold">SSO</span>
            </div>
            <h1 className="text-2xl font-semibold text-slate-900 dark:text-slate-100">Initialize Admin</h1>
            <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">Create your first administrator account</p>
          </div>

          {isComplete ? (
            <div className="space-y-4 rounded-2xl border border-emerald-200 bg-emerald-50 p-4 dark:border-emerald-600/30 dark:bg-emerald-600/10">
              <p className="text-sm font-semibold text-emerald-900 dark:text-emerald-200">✓ Admin account created successfully!</p>
              <p className="text-xs text-emerald-700 dark:text-emerald-300">Redirecting to login page...</p>
            </div>
          ) : (
            <form className="space-y-4" onSubmit={handleSubmit}>
              <label className="block">
                <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700">Email Address</span>
                <input
                  type="email"
                  required
                  value={form.email}
                  onChange={(e) => setForm({ ...form, email: e.target.value })}
                  placeholder="admin@example.com"
                  disabled={isLoading}
                  className="mt-2 w-full rounded-2xl border border-amber-100 bg-white px-4 py-3 text-sm text-slate-900 shadow-sm focus:border-amber-400 focus:outline-none disabled:opacity-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
                />
              </label>

              <label className="block">
                <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700">Username</span>
                <input
                  type="text"
                  required
                  value={form.username}
                  onChange={(e) => setForm({ ...form, username: e.target.value })}
                  placeholder="admin"
                  disabled={isLoading}
                  className="mt-2 w-full rounded-2xl border border-amber-100 bg-white px-4 py-3 text-sm text-slate-900 shadow-sm focus:border-amber-400 focus:outline-none disabled:opacity-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
                />
              </label>

              <label className="block">
                <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700">Password</span>
                <input
                  type="password"
                  required
                  value={form.password}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                  placeholder="••••••••"
                  minLength={8}
                  disabled={isLoading}
                  className="mt-2 w-full rounded-2xl border border-amber-100 bg-white px-4 py-3 text-sm text-slate-900 shadow-sm focus:border-amber-400 focus:outline-none disabled:opacity-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
                />
                <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">Minimum 8 characters</p>
              </label>

              <label className="block">
                <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700">Confirm Password</span>
                <input
                  type="password"
                  required
                  value={form.confirmPassword}
                  onChange={(e) => setForm({ ...form, confirmPassword: e.target.value })}
                  placeholder="••••••••"
                  minLength={8}
                  disabled={isLoading}
                  className="mt-2 w-full rounded-2xl border border-amber-100 bg-white px-4 py-3 text-sm text-slate-900 shadow-sm focus:border-amber-400 focus:outline-none disabled:opacity-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100"
                />
              </label>

              {message && (
                <div
                  className={`rounded-2xl p-4 text-sm ${
                    message.variant === "error"
                      ? "border border-rose-200 bg-rose-50 text-rose-900 dark:border-rose-600/30 dark:bg-rose-600/10 dark:text-rose-200"
                      : "border border-emerald-200 bg-emerald-50 text-emerald-900 dark:border-emerald-600/30 dark:bg-emerald-600/10 dark:text-emerald-200"
                  }`}
                >
                  {message.text}
                </div>
              )}

              <button
                type="submit"
                disabled={isLoading}
                className="mt-6 w-full rounded-2xl bg-slate-900 px-4 py-3 text-sm font-semibold text-white transition hover:-translate-y-0.5 disabled:opacity-50 disabled:hover:translate-y-0 dark:bg-amber-600"
              >
                {isLoading ? "Creating Account..." : "Create Admin Account"}
              </button>
            </form>
          )}
        </div>

        <p className="mt-6 text-center text-xs text-slate-500 dark:text-slate-400">
          SSO Server Admin Console
        </p>
      </div>
    </main>
  );
}
