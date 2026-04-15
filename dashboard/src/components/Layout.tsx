import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useAuthStore } from '../store/auth'

const NAV = [
  { to: '/',        label: 'Scans',  exact: true },
  { to: '/agents',  label: 'Agents', exact: false },
]

export default function Layout() {
  const logout = useAuthStore((s) => s.logout)
  const nav    = useNavigate()

  function handleLogout() {
    logout()
    nav('/login', { replace: true })
  }

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

        <div className="ml-auto">
          <button
            onClick={handleLogout}
            className="text-[11px] text-text-dim hover:text-text transition-colors"
          >
            Sign out
          </button>
        </div>
      </header>

      {/* Page content */}
      <main className="flex-1 overflow-hidden">
        <Outlet />
      </main>
    </div>
  )
}
