import { Routes, Route, Navigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useAuthStore } from './store/auth'
import { api } from './api/client'
import Layout     from './components/Layout'
import Login      from './pages/Login'
import License    from './pages/License'
import Dashboard  from './pages/Dashboard'
import NewScan    from './pages/NewScan'
import ScanDetail from './pages/ScanDetail'
import Agents     from './pages/Agents'

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
  if (isLoading) return null
  if (data && !data.licensed) return <Navigate to="/license" replace />
  return <>{children}</>
}

function RequireAuth({ children }: { children: React.ReactNode }) {
  const token = useAuthStore((s) => s.token)
  return token ? <>{children}</> : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <Routes>
      {/* License activation — accessible without a license or auth token */}
      <Route path="/license" element={<License />} />

      {/* All other routes require a valid license first */}
      <Route path="/login" element={<RequireLicense><Login /></RequireLicense>} />
      <Route
        element={
          <RequireLicense>
            <RequireAuth>
              <Layout />
            </RequireAuth>
          </RequireLicense>
        }
      >
        <Route index              element={<Dashboard />} />
        <Route path="scans/new"   element={<NewScan />} />
        <Route path="scans/:id"   element={<ScanDetail />} />
        <Route path="agents"      element={<Agents />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
