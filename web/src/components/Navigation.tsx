import { useEffect, useState } from "react";
import { logout } from "../utils/auth";

interface UserInfo {
  id: string;
  email: string;
  username: string;
}

export default function Navigation() {
  const [user, setUser] = useState<UserInfo | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadUser = async () => {
      try {
        const response = await fetch("/api/user", {
          credentials: "include",
        });
        if (response.ok) {
          const data = await response.json();
          setUser(data);
        }
      } catch (error) {
        console.error("Failed to load user:", error);
      } finally {
        setLoading(false);
      }
    };

    loadUser();
  }, []);

  const handleLogout = async () => {
    await logout();
  };

  return (
    <nav className="w-full sticky top-0 z-40 border-b border-amber-100/70 bg-white/90 text-slate-900 backdrop-blur dark:border-slate-800 dark:bg-slate-950/70 dark:text-slate-100">
      <div className="mx-auto flex w-full max-w-6xl flex-wrap items-center justify-between gap-4 px-6 py-4">
        <div className="flex items-center gap-3">
          <span className="inline-flex h-9 w-9 items-center justify-center rounded-2xl bg-amber-100 text-amber-700 dark:bg-amber-600/20 dark:text-amber-400">
            SSO
          </span>
          <div>
            <p className="text-sm uppercase tracking-[0.28em] text-amber-600 dark:text-amber-400">
              Console
            </p>
            <h1 className="text-lg font-semibold">SSO Server</h1>
          </div>
        </div>

        <ul className="flex flex-wrap items-center gap-3 text-sm font-semibold">
          <li>
            <a
              href="/"
              className="rounded-full px-3 py-2 text-slate-600 transition hover:bg-amber-50 hover:text-slate-900 dark:text-slate-300 dark:hover:bg-slate-800"
            >
              Home
            </a>
          </li>
          <li>
            <a
              href="/panel/clients"
              className="rounded-full px-3 py-2 text-slate-600 transition hover:bg-amber-50 hover:text-slate-900 dark:text-slate-300 dark:hover:bg-slate-800"
            >
              Clients
            </a>
          </li>
          <li>
            <a
              href="/panel/users"
              className="rounded-full px-3 py-2 text-slate-600 transition hover:bg-amber-50 hover:text-slate-900 dark:text-slate-300 dark:hover:bg-slate-800"
            >
              Users
            </a>
          </li>
          <li>
            <a
              href="/panel/roles"
              className="rounded-full px-3 py-2 text-slate-600 transition hover:bg-amber-50 hover:text-slate-900 dark:text-slate-300 dark:hover:bg-slate-800"
            >
              Roles
            </a>
          </li>
          <li>
            <a
              href="/panel/binding"
              className="rounded-full px-3 py-2 text-slate-600 transition hover:bg-amber-50 hover:text-slate-900 dark:text-slate-300 dark:hover:bg-slate-800"
            >
              Binding
            </a>
          </li>
          <li>
            <a
              href="/panel/scopes"
              className="rounded-full px-3 py-2 text-slate-600 transition hover:bg-amber-50 hover:text-slate-900 dark:text-slate-300 dark:hover:bg-slate-800"
            >
              Scopes
            </a>
          </li>

          {!loading && user ? (
            <>
              <li className="text-slate-600 dark:text-slate-400">
                {user.username} ({user.email})
              </li>
              <li>
                <button
                  onClick={handleLogout}
                  className="rounded-full border border-red-200 px-3 py-2 text-red-700 transition hover:bg-red-100 dark:border-red-600/60 dark:text-red-400 dark:hover:bg-red-600/20"
                >
                  Logout
                </button>
              </li>
            </>
          ) : (
            <li>
              <a
                href="/login"
                className="rounded-full border border-amber-200 px-3 py-2 text-amber-700 transition hover:bg-amber-100 dark:border-amber-600/60 dark:text-amber-300 dark:hover:bg-amber-600/20"
              >
                Login
              </a>
            </li>
          )}
        </ul>
      </div>
    </nav>
  );
}
