import type { ReactNode } from "react";

type PageShellProps = {
  title: string;
  subtitle: string;
  actions?: ReactNode;
  children: ReactNode;
};

export default function PageShell({ title, subtitle, actions, children }: PageShellProps) {
  return (
    <main className="relative grow w-full bg-gray-100 px-6 py-10 dark:bg-slate-950">
      <div className="mx-auto w-full max-w-6xl space-y-6">
        <section className="rounded-3xl border border-amber-200/70 bg-white/95 p-8 backdrop-blur dark:border-amber-900/50 dark:bg-slate-900/80">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="space-y-2">
              <p className="text-xs font-semibold uppercase tracking-[0.42em] text-amber-600">Admin Console</p>
              <h1 className="text-3xl font-semibold text-slate-900 dark:text-slate-100">{title}</h1>
              <p className="text-sm text-slate-600 dark:text-slate-300">{subtitle}</p>
            </div>
            {actions ? <div className="flex flex-wrap gap-3">{actions}</div> : null}
          </div>
        </section>
        {children}
      </div>
    </main>
  );
}
