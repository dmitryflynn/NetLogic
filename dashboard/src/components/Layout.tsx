import { NavLink, Outlet, Link } from 'react-router-dom'
import { UserButton } from '@clerk/clerk-react'

const NAV = [
  { to: '/',         label: 'Scans',    icon: '◈', exact: true },
  { to: '/targets',  label: 'Targets',  icon: '◎', exact: false },
  { to: '/agents',   label: 'Agents',   icon: '⬡', exact: false },
  { to: '/settings', label: 'Settings', icon: '⚙', exact: false },
]

export default function Layout() {
  return (
    <div className="h-screen flex bg-base text-text overflow-hidden">
      {/* Sidebar */}
      <aside className="w-56 shrink-0 flex flex-col border-r border-border bg-sidebar">
        <div className="px-5 py-5 border-b border-border/60">
          <Link to="/" className="block group">
            <p className="font-display font-bold text-[15px] text-text-bright tracking-tight">
              Net<span className="text-accent">Logic</span>
            </p>
            <p className="text-[10px] text-text-dim mt-0.5 tracking-wide uppercase">
              Attack Surface Intelligence
            </p>
          </Link>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1">
          {NAV.map(({ to, label, icon, exact }) => (
            <NavLink
              key={to}
              to={to}
              end={exact}
              className={({ isActive }) =>
                `nav-item ${isActive ? 'nav-item-active' : 'nav-item-idle'}`
              }
            >
              <span className="text-[14px] opacity-70" aria-hidden>{icon}</span>
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="px-3 py-4 border-t border-border/60">
          <NavLink
            to="/scans/new"
            className="btn btn-primary w-full justify-center text-[13px]"
          >
            + New Scan
          </NavLink>
        </div>

        <div className="px-4 py-3 border-t border-border/60 flex items-center justify-between">
          <span className="text-[10px] text-text-dim">Account</span>
          <UserButton afterSignOutUrl="/login" />
        </div>
      </aside>

      {/* Main column */}
      <div className="flex-1 flex flex-col min-w-0 min-h-0">
        <main className="flex-1 min-h-0 overflow-y-auto bg-grid-fade">
          <Outlet />
        </main>

        <footer className="shrink-0 h-8 flex items-center justify-center gap-3 px-6 border-t border-border bg-panel/80 text-text-dim text-[10px]">
          <span>© {new Date().getFullYear()} NetLogic</span>
          <span aria-hidden>·</span>
          <Link to="/terms" className="hover:text-text transition-colors">Terms</Link>
          <span aria-hidden>·</span>
          <Link to="/privacy" className="hover:text-text transition-colors">Privacy</Link>
        </footer>
      </div>
    </div>
  )
}
