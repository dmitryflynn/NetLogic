import { NavLink, Outlet, Link } from 'react-router-dom'
import { UserButton } from '@clerk/clerk-react'
import { Brand, IconAgents, IconScan, IconSettings, IconTarget } from './Brand'

const NAV = [
  { to: '/',         label: 'Scans',    exact: true,  icon: IconScan },
  { to: '/targets',  label: 'Targets',  exact: false, icon: IconTarget },
  { to: '/agents',   label: 'Agents',   exact: false, icon: IconAgents },
  { to: '/settings', label: 'Settings', exact: false, icon: IconSettings },
]

export default function Layout() {
  return (
    <div className="h-screen flex site-bg text-text overflow-hidden relative">
      <div className="site-grid pointer-events-none absolute inset-0" />
      <div className="site-noise pointer-events-none absolute inset-0" />

      <aside className="relative z-10 w-[15.5rem] shrink-0 m-3 mr-0 flex flex-col glass-strong rounded-2xl overflow-hidden">
        <div className="px-5 py-6">
          <Link to="/" className="block">
            <Brand size="sm" subtitle />
          </Link>
        </div>

        <nav className="flex-1 px-3 space-y-0.5">
          {NAV.map(({ to, label, exact, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={exact}
              className={({ isActive }) =>
                `nav-item ${isActive ? 'nav-item-active' : 'nav-item-idle'}`
              }
            >
              <Icon className="w-[15px] h-[15px] opacity-80" />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="px-3 pb-3">
          <NavLink to="/scans/new" className="btn btn-primary w-full justify-center">
            New scan
          </NavLink>
        </div>

        <div className="px-4 py-3.5 border-t border-white/5 flex items-center justify-between">
          <span className="text-[11px] text-text-dim">Account</span>
          <UserButton afterSignOutUrl="/login" />
        </div>
      </aside>

      <div className="relative z-10 flex-1 flex flex-col min-w-0 min-h-0">
        <main className="flex-1 min-h-0 overflow-y-auto">
          <Outlet />
        </main>
        <footer className="shrink-0 h-9 flex items-center justify-center gap-3 px-6 text-text-dim text-[11px]">
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
