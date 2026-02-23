import { useState, useEffect } from "react";

declare global {
  interface Window {
    __resetToken?: string;
    __redirectUrl?: string;
  }
}

export default function ResetPasswordPage() {
  const [token, setToken] = useState("");
  const [redirectUrl, setRedirectUrl] = useState("/");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [message, setMessage] = useState<{ text: string; variant: "info" | "success" | "error" }>({ text: "", variant: "info" });
  const [isLoading, setIsLoading] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);

  useEffect(() => {
    if (typeof window !== "undefined") {
      // Get token and redirect_url from injected window variables
      const injectedToken = window.__resetToken;
      const injectedRedirectUrl = window.__redirectUrl;
      
      if (!injectedToken) {
        setMessage({
          text: "Invalid reset link. Please request a new password reset.",
          variant: "error",
        });
      } else {
        setToken(injectedToken);
        setRedirectUrl(injectedRedirectUrl || "/");
      }
    }
  }, []);

  const messageClasses = {
    info: "text-slate-600 dark:text-slate-400",
    success: "text-emerald-600 dark:text-emerald-400",
    error: "text-rose-600 dark:text-rose-400",
  };

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    if (newPassword !== confirmPassword) {
      setMessage({
        text: "Passwords do not match",
        variant: "error",
      });
      return;
    }

    if (newPassword.length < 8) {
      setMessage({
        text: "Password must be at least 8 characters long",
        variant: "error",
      });
      return;
    }

    setIsLoading(true);
    setMessage({ text: "Resetting password...", variant: "info" });

    try {
      const response = await fetch("/auth/email/reset-password", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        credentials: "include",
        body: JSON.stringify({
          token,
          new_password: newPassword,
          redirect_url: redirectUrl || "/",
        }),
      });

      if (response.redirected) {
        window.location.assign(response.url);
        return;
      }

      const result = await response.json().catch(() => ({}));

      if (!response.ok) {
        setMessage({
          text: result.error_description || result.error || "Failed to reset password",
          variant: "error",
        });
        setIsLoading(false);
        return;
      }

      setIsSuccess(true);
      setMessage({
        text: "Password reset successfully! Redirecting...",
        variant: "success",
      });
      
      setTimeout(() => {
        window.location.href = "/";
      }, 2000);
    } catch (err) {
      setMessage({
        text: err instanceof Error ? err.message : "Something went wrong",
        variant: "error",
      });
      setIsLoading(false);
    }
  };

  return (
    <main className="relative min-h-screen w-full bg-gray-100 dark:bg-slate-950 px-6 py-10 sm:py-14">
      <div className="relative mx-auto w-full max-w-2xl">
        <section className="rounded-3xl border border-amber-200/60 dark:border-amber-900/40 bg-white/95 dark:bg-slate-800/90 p-8 backdrop-blur">
          <div className="space-y-2">
            <h1 className="text-3xl font-semibold text-slate-900 dark:text-slate-100">Reset Your Password</h1>
            <p className="text-sm text-slate-600 dark:text-slate-400">Enter your new password to regain access to your account.</p>
          </div>

          {!isSuccess && token && (
            <form className="mt-6 space-y-4" onSubmit={handleSubmit}>
              <label className="block">
                <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700 dark:text-amber-600">New Password</span>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Enter your new password"
                  required
                  className="mt-2 w-full rounded-2xl border border-amber-100 dark:border-slate-600 bg-white dark:bg-slate-700 px-4 py-3 text-sm text-slate-900 dark:text-slate-100 placeholder-slate-500 dark:placeholder-slate-500 focus:border-amber-400 dark:focus:border-amber-500 focus:outline-none"
                />
              </label>
              <label className="block">
                <span className="text-xs font-semibold uppercase tracking-[0.14em] text-amber-700 dark:text-amber-600">Confirm Password</span>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Confirm your password"
                  required
                  className="mt-2 w-full rounded-2xl border border-amber-100 dark:border-slate-600 bg-white dark:bg-slate-700 px-4 py-3 text-sm text-slate-900 dark:text-slate-100 placeholder-slate-500 dark:placeholder-slate-500 focus:border-amber-400 dark:focus:border-amber-500 focus:outline-none"
                />
              </label>
              <button
                type="submit"
                disabled={isLoading}
                className="w-full rounded-2xl bg-slate-900 dark:bg-amber-600 px-4 py-3 text-sm font-semibold text-white shadow-slate-900/20 dark:shadow-amber-600/30 transition hover:-translate-y-0.5 dark:hover:bg-amber-500 disabled:opacity-50"
              >
                {isLoading ? "Resetting Password..." : "Reset Password"}
              </button>
            </form>
          )}

          {message.text && (
            <div className={`mt-4 min-h-6 text-sm ${messageClasses[message.variant]}`}>
              {message.text}
            </div>
          )}

          {isSuccess && (
            <div className="mt-6 rounded-2xl border border-emerald-200 dark:border-emerald-900/40 bg-emerald-50 dark:bg-emerald-900/10 p-4">
              <div className="flex gap-3">
                <div className="shrink-0">
                  <svg className="h-5 w-5 text-emerald-600 dark:text-emerald-400" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                  </svg>
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-emerald-800 dark:text-emerald-200">Password Reset Successful</h3>
                  <p className="mt-2 text-sm text-emerald-700 dark:text-emerald-300">
                    Your password has been successfully reset. You can now log in with your new password.
                  </p>
                </div>
              </div>
            </div>
          )}
        </section>
      </div>
    </main>
  );
}
