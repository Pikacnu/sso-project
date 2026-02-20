import { useState, useEffect } from "react";

export default function LoginPage() {
  const [tab, setTab] = useState<"login" | "register">("login");
  const [message, setMessage] = useState<{ text: string; variant: "info" | "success" | "error" }>({ text: "", variant: "info" });
  const [isLoading, setIsLoading] = useState(false);
  const [flowId, setFlowId] = useState("");
  const [redirectUrl, setRedirectUrl] = useState("");
  const [showPopup, setShowPopup] = useState(false);

  useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      setFlowId(params.get("flow_id") || "");
      setRedirectUrl(params.get("redirect_url") || "");
    }
  }, []);

  const messageClasses = {
    info: "text-slate-600 dark:text-slate-400",
    success: "text-emerald-600 dark:text-emerald-400",
    error: "text-rose-600 dark:text-rose-400",
  };

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setIsLoading(true);
    setMessage({ text: "Working on it...", variant: "info" });

    const form = e.currentTarget as HTMLFormElement;
    const formData = new FormData(form);
    const payload = Object.fromEntries(formData.entries());

    if (flowId) payload.flow_id = flowId;
    if (redirectUrl) payload.redirect_url = redirectUrl;

    const endpoint = tab === "register" ? "/auth/email/register" : "/auth/email/login";

    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        credentials: "include",
        redirect: "follow",
        body: JSON.stringify(payload),
      });

      if (response.redirected) {
        window.location.assign(response.url);
        return;
      }

      const result = await response.json().catch(() => ({}));
      if (!response.ok) {
        setMessage({
          text: result.error_description || result.error || "Request failed",
          variant: "error",
        });
        setIsLoading(false);
        return;
      }

      setMessage({
        text: result.message || "Success",
        variant: "success",
      });
      form.reset();
      setIsLoading(false);
    } catch (err) {
      setMessage({
        text: err instanceof Error ? err.message : "Something went wrong",
        variant: "error",
      });
      setIsLoading(false);
    }
  };

  const getOAuthUrl = (provider: string) => {
    if (typeof window === "undefined") return `#`;
    const url = new URL(`/auth/${provider}/login`, window.location.origin);
    if (flowId) url.searchParams.set("flow_id", flowId);
    if (redirectUrl) url.searchParams.set("redirect_url", redirectUrl);
    return url.toString();
  };

  return (
    <main className="relative min-h-screen w-full bg-gray-100 dark:bg-slate-950 px-6 py-10 sm:py-14">
      <div className="relative mx-auto w-full max-w-2xl">
        <section className="rounded-3xl border border-amber-200/60 dark:border-amber-900/40 bg-white/95 dark:bg-slate-800/90 p-8 backdrop-blur">
          <div className="space-y-2">
            <h1 className="text-3xl font-semibold text-slate-900 dark:text-slate-100">Email Login</h1>
            <p className="text-sm text-slate-600 dark:text-slate-400">Sign in or create an account to continue.</p>
          </div>

          <div className="mt-6 flex gap-3 rounded-full border border-amber-100 dark:border-amber-900/50 bg-amber-50 dark:bg-slate-700/50 p-1">
            {(["login", "register"] as const).map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => {
                  setTab(t);
                  setMessage({ text: "", variant: "info" });
                }}
                className={`flex-1 rounded-full px-4 py-2 text-sm font-semibold transition ${
                  tab === t
                    ? "bg-white dark:bg-slate-600 text-slate-900 dark:text-slate-100"
                    : "text-slate-600 dark:text-slate-400"
                }`}
              >
                {t === "login" ? "Login" : "Register"}
              </button>
            ))}
          </div>

          {tab === "login" && (
            <form className="mt-6 space-y-4" onSubmit={handleSubmit}>
              <label className="block">
                <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700 dark:text-amber-600">Email</span>
                <input
                  type="email"
                  name="email"
                  placeholder="you@example.com"
                  autoComplete="email"
                  required
                  className="mt-2 w-full rounded-2xl border border-amber-100 dark:border-slate-600 bg-white dark:bg-slate-700 px-4 py-3 text-sm text-slate-900 dark:text-slate-100 placeholder-slate-500 dark:placeholder-slate-500  focus:border-amber-400 dark:focus:border-amber-500 focus:outline-none"
                />
              </label>
              <label className="block">
                <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700 dark:text-amber-600">Password</span>
                <input
                  type="password"
                  name="password"
                  placeholder="Your password"
                  autoComplete="current-password"
                  required
                  className="mt-2 w-full rounded-2xl border border-amber-100 dark:border-slate-600 bg-white dark:bg-slate-700 px-4 py-3 text-sm text-slate-900 dark:text-slate-100 placeholder-slate-500 dark:placeholder-slate-500  focus:border-amber-400 dark:focus:border-amber-500 focus:outline-none"
                />
              </label>
              <button
                type="submit"
                disabled={isLoading}
                className="w-full rounded-2xl bg-slate-900 dark:bg-amber-600 px-4 py-3 text-sm font-semibold text-white  shadow-slate-900/20 dark:shadow-amber-600/30 transition hover:-translate-y-0.5 dark:hover:bg-amber-500 disabled:opacity-50"
              >
                {isLoading ? "Logging in..." : "Login"}
              </button>
            </form>
          )}

          {tab === "register" && (
            <form className="mt-6 space-y-4" onSubmit={handleSubmit}>
              <label className="block">
                <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700 dark:text-amber-600">Email</span>
                <input
                  type="email"
                  name="email"
                  placeholder="you@example.com"
                  autoComplete="email"
                  required
                  className="mt-2 w-full rounded-2xl border border-amber-100 dark:border-slate-600 bg-white dark:bg-slate-700 px-4 py-3 text-sm text-slate-900 dark:text-slate-100 placeholder-slate-500 dark:placeholder-slate-500  focus:border-amber-400 dark:focus:border-amber-500 focus:outline-none"
                />
              </label>
              <label className="block">
                <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700 dark:text-amber-600">Password</span>
                <input
                  type="password"
                  name="password"
                  placeholder="Create a password"
                  autoComplete="new-password"
                  required
                  className="mt-2 w-full rounded-2xl border border-amber-100 dark:border-slate-600 bg-white dark:bg-slate-700 px-4 py-3 text-sm text-slate-900 dark:text-slate-100 placeholder-slate-500 dark:placeholder-slate-500  focus:border-amber-400 dark:focus:border-amber-500 focus:outline-none"
                />
              </label>
              <label className="block">
                <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700 dark:text-amber-600">Username (optional)</span>
                <input
                  type="text"
                  name="username"
                  autoComplete="username"
                  placeholder="Display name"
                  className="mt-2 w-full rounded-2xl border border-amber-100 dark:border-slate-600 bg-white dark:bg-slate-700 px-4 py-3 text-sm text-slate-900 dark:text-slate-100 placeholder-slate-500 dark:placeholder-slate-500  focus:border-amber-400 dark:focus:border-amber-500 focus:outline-none"
                />
              </label>
              <button
                type="submit"
                disabled={isLoading}
                className="w-full rounded-2xl bg-slate-900 dark:bg-amber-600 px-4 py-3 text-sm font-semibold text-white  shadow-slate-900/20 dark:shadow-amber-600/30 transition hover:-translate-y-0.5 dark:hover:bg-amber-500 disabled:opacity-50"
              >
                {isLoading ? "Creating account..." : "Create Account"}
              </button>
            </form>
          )}

          {message.text && (
            <div className={`mt-4 min-h-6 text-sm ${messageClasses[message.variant]}`}>
              {message.text}
            </div>
          )}

          <div className="mt-6 flex items-center gap-3 text-xs uppercase tracking-[0.18em] text-amber-700 dark:text-amber-700">
            <span className="h-px flex-1 bg-amber-200/70 dark:bg-slate-700"></span>
            Or continue with
            <span className="h-px flex-1 bg-amber-200/70 dark:bg-slate-700"></span>
          </div>

          <div className="mt-5 grid gap-3 grid-cols-2">
            <a
              href={getOAuthUrl("google")}
              className="flex items-center justify-center rounded-2xl border border-amber-100 dark:border-slate-600 bg-white dark:bg-slate-700 px-4 py-3 text-sm font-semibold text-slate-800 dark:text-slate-200  transition hover:-translate-y-0.5 hover:border-amber-300 dark:hover:border-amber-600 dark:hover:bg-slate-600"
            >
              Google
            </a>
            <a
              href={getOAuthUrl("discord")}
              className="flex items-center justify-center rounded-2xl border border-amber-100 dark:border-slate-600 bg-white dark:bg-slate-700 px-4 py-3 text-sm font-semibold text-slate-800 dark:text-slate-200  transition hover:-translate-y-0.5 hover:border-amber-300 dark:hover:border-amber-600 dark:hover:bg-slate-600"
            >
              Discord
            </a>
          </div>

          <button
            onClick={() => setShowPopup(!showPopup)}
            className="mt-6 text-sm text-slate-500 dark:text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 underline"
          >
            What is email verification?
          </button>
        </section>
      </div>

      {showPopup && (
        <div className="fixed inset-0 bg-black/50 dark:bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="rounded-3xl bg-white dark:bg-slate-800 p-8 max-w-md w-full dark:border dark:border-slate-700">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-semibold text-slate-900 dark:text-slate-100">Email Verification</h2>
              <button
                onClick={() => setShowPopup(false)}
                className="text-2xl text-slate-400 dark:text-slate-500 hover:text-slate-600 dark:hover:text-slate-300"
              >
                ✕
              </button>
            </div>
            <p className="text-sm text-slate-600 dark:text-slate-400 mb-4">
              We will send a verification link to your email before enabling access. This flow can also return a token for external integrations.
            </p>
            <ul className="space-y-3 text-sm text-slate-600 dark:text-slate-400">
              <li className="flex items-center gap-2">
                <span className="inline-flex h-2.5 w-2.5 rounded-full bg-amber-400 dark:bg-amber-500"></span>
                OAuth flow aware
              </li>
              <li className="flex items-center gap-2">
                <span className="inline-flex h-2.5 w-2.5 rounded-full bg-amber-400 dark:bg-amber-500"></span>
                Flow ID passthrough
              </li>
              <li className="flex items-center gap-2">
                <span className="inline-flex h-2.5 w-2.5 rounded-full bg-amber-400 dark:bg-amber-500"></span>
                Redirect ready
              </li>
            </ul>
            <button
              onClick={() => setShowPopup(false)}
              className="mt-6 w-full rounded-2xl bg-slate-900 dark:bg-amber-600 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800 dark:hover:bg-amber-500 transition"
            >
              Got it
            </button>
          </div>
        </div>
      )}
    </main>
  );
}
