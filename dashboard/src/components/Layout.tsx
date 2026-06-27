import { NavLink, Outlet, Link } from 'react-router-dom'
import { UserButton } from '@clerk/clerk-react'

const NAV = [
  { to: '/',         label: 'Scans',    exact: true },
  { to: '/targets',  label: 'Targets',  exact: false },
  { to: '/agents',   label: 'Agents',   exact: false },
  { to: '/settings', label: 'Settings', exact: false },
]

export default function Layout() {
  return (
    <div className="h-screen flex flex-col bg-base text-text overflow-hidden">
      {/* Top nav */}
      <header className="shrink-0 h-10 flex items-center gap-6 px-6 border-b border-border bg-panel">
        <span className="font-display font-bold text-[13px] text-text-bright tracking-widest">
          NET<span className="text-accent">LOGIC</span>
        </span>

        <nav className="flex items-center gap-1">
          {NAV.map(({ to, label, exact }) => (
            <NavLink
              key={to}
              to={to}
              end={exact}
              className={({ isActive }) =>
                `px-3 py-1 rounded text-[12px] transition-colors ${
                  isActive
                    ? 'bg-accent/10 text-accent'
                    : 'text-text-dim hover:text-text hover:bg-elevated'
                }`
              }
            >
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="ml-auto flex items-center">
          <UserButton afterSignOutUrl="/login" />
        </div>
      </header>

      {/* Page content. overflow-y-auto (not hidden) so pages that render tall
          content (New Scan, Agents) scroll; pages with their own internal scroll
          (Dashboard, Scan detail) are h-full and fill this definite flex height. */}
      <main className="flex-1 min-h-0 overflow-y-auto">
        <Outlet />
      </main>

      {/* Persistent legal footer */}
      <footer className="shrink-0 h-7 flex items-center justify-center gap-3 px-6 border-t border-border bg-panel text-text-dim text-[10px]">
        <span>© {new Date().getFullYear()} NetLogic</span>
        <span aria-hidden>·</span>
        <Link to="/terms" className="hover:text-text">Terms</Link>
        <span aria-hidden>·</span>
        <Link to="/privacy" className="hover:text-text">Privacy</Link>
      </footer>
    </div>
  )
}
