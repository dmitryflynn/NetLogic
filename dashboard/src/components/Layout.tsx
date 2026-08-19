import { NavLink, Outlet, Link } from 'react-router-dom'
import { UserButton } from '@clerk/clerk-react'
import { Brand, IconAgents, IconScan, IconSettings, IconTarget } from './Brand'

const NAV = [
  { to: '/',         label: 'scans',    exact: true,  icon: IconScan,    index: '01' },
  { to: '/targets',  label: 'targets',  exact: false, icon: IconTarget,  index: '02' },
  { to: '/agents',   label: 'agents',   exact: false, icon: IconAgents,  index: '03' },
  { to: '/settings', label: 'settings', exact: false, icon: IconSettings, index: '04' },
]

function Radar() {
  return (
    <div className="radar" aria-hidden>
      <div className="r-ring" />
      <div className="r-ring r2" />
      <div className="r-ring r3" />
      <div className="r-cross" />
      <div className="r-cross h" />
      <div className="r-sweep" />
    </div>
  )
}

export default function Layout() {
  return (
    <div className="h-screen flex site-bg text-text overflow-hidden relative">
      <div className="site-grid pointer-events-none absolute inset-0" />
      <div className="site-noise pointer-events-none absolute inset-0" />
      <Radar />

      <aside className="relative z-10 w-[15.5rem] shrink-0 m-3 mr-0 flex flex-col glass-strong rounded-[28px] overflow-hidden">
        <div className="px-5 py-6">
          <Link to="/" className="block" aria-label="netlogic home">
            <Brand size="sm" subtitle />
          </Link>
        </div>

        <nav className="flex-1 px-3 space-y-0.5">
          {NAV.map(({ to, label, exact, icon: Icon, index }) => (
            <NavLink
              key={to}
              to={to}
              end={exact}
              className={({ isActive }) =>
                `nav-item ${isActive ? 'nav-item-active' : 'nav-item-idle'}`
              }
            >
              <span className="nav-index">{index}</span>
              <Icon className="w-[15px] h-[15px] opacity-80" />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="px-3 pb-3">
          <NavLink to="/scans/new" className="btn btn-primary w-full justify-center">
            new scan
          </NavLink>
        </div>

        <div className="px-4 py-3.5 border-t border-border/80 flex items-center justify-between">
          <span className="font-mono text-[10px] tracking-[0.16em] uppercase text-text-dim">account</span>
          <UserButton afterSignOutUrl="/login" />
        </div>
      </aside>

      <div className="relative z-10 flex-1 flex flex-col min-w-0 min-h-0">
        <main className="flex-1 min-h-0 overflow-y-auto">
          <Outlet />
        </main>
        <footer className="shrink-0 h-9 flex items-center justify-center gap-3 px-6 text-text-dim text-[11px] font-mono tracking-[0.08em]">
          <span>© {new Date().getFullYear()} netlogic</span>
          <span aria-hidden>·</span>
          <Link to="/terms" className="hover:text-accent transition-colors">terms</Link>
          <span aria-hidden>·</span>
          <Link to="/privacy" className="hover:text-accent transition-colors">privacy</Link>
        </footer>
      </div>
    </div>
  )
}
