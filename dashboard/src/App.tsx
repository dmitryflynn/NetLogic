import { Routes, Route, Navigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { SignedIn, SignedOut, RedirectToSignIn } from '@clerk/clerk-react'
import { api } from './api/client'
import Layout        from './components/Layout'
import Login         from './pages/Login'
import SignUpPage    from './pages/SignUp'
import License       from './pages/License'
import { TermsPage, PrivacyPage } from './pages/Legal'
import Dashboard     from './pages/Dashboard'
import NewScan       from './pages/NewScan'
import ScanDetail    from './pages/ScanDetail'
import Agents        from './pages/Agents'
import Targets       from './pages/Targets'
import TargetTimeline from './pages/TargetTimeline'
import Settings      from './pages/Settings'
import ErrorBoundary from './components/ErrorBoundary'

interface LicenseStatus {
  licensed: boolean
  plan: string | null
}

function RequireLicense({ children }: { children: React.ReactNode }) {
  const { data, isLoading } = useQuery<LicenseStatus>({
    queryKey: ['license'],
    queryFn:  () => api.get<LicenseStatus>('/license'),
    staleTime: 60_000,
    retry: false,
  })
  if (isLoading) {
    return (
      <div className="min-h-screen site-bg relative flex items-center justify-center">
        <div className="site-grid pointer-events-none absolute inset-0" />
        <div className="text-center space-y-3 relative z-10">
          <p className="font-display text-2xl font-bold text-text-bright tracking-[0.02em]">netlogic</p>
          <p className="text-text-dim text-[13px]">Loading…</p>
        </div>
      </div>
    )
  }
  if (data && !data.licensed) return <Navigate to="/license" replace />
  return <>{children}</>
}

function RequireAuth({ children }: { children: React.ReactNode }) {
  // Clerk owns the session. SignedIn/SignedOut render once Clerk has loaded;
  // a signed-out user is bounced to the Clerk <SignIn> mounted at /login.
  return (
    <>
      <SignedIn>{children}</SignedIn>
      <SignedOut><RedirectToSignIn /></SignedOut>
    </>
  )
}

export default function App() {
  return (
    <Routes>
      {/* License activation — accessible without a license or auth token */}
      <Route path="/license" element={<License />} />

      {/* Legal docs — always public so the sign-up consent links resolve */}
      <Route path="/terms" element={<TermsPage />} />
      <Route path="/privacy" element={<PrivacyPage />} />

      {/* All other routes require a valid license first */}
      <Route path="/login/*" element={<RequireLicense><Login /></RequireLicense>} />
      <Route path="/sign-up/*" element={<RequireLicense><SignUpPage /></RequireLicense>} />
      <Route
        element={
          <RequireLicense>
            <RequireAuth>
              <Layout />
            </RequireAuth>
          </RequireLicense>
        }
      >
        <Route index              element={<ErrorBoundary><Dashboard /></ErrorBoundary>} />
        <Route path="scans/new"   element={<ErrorBoundary><NewScan /></ErrorBoundary>} />
        <Route path="scans/:id"   element={<ErrorBoundary><ScanDetail /></ErrorBoundary>} />
        <Route path="agents"      element={<ErrorBoundary><Agents /></ErrorBoundary>} />
        <Route path="targets"     element={<ErrorBoundary><Targets /></ErrorBoundary>} />
        <Route path="targets/:target" element={<ErrorBoundary><TargetTimeline /></ErrorBoundary>} />
        <Route path="settings"    element={<ErrorBoundary><Settings /></ErrorBoundary>} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
