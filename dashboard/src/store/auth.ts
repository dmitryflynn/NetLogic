import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface AuthState {
  token: string | null
  orgId: string | null
  apiKey: string | null          // saved for auto-relogin
  login: (apiKey: string) => Promise<void>
  logout: () => void
}

const BASE = (import.meta.env.VITE_API_URL ?? '') + '/v1'

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      token:  null,
      orgId:  null,
      apiKey: null,

      login: async (apiKey: string) => {
        const res = await fetch(`${BASE}/auth/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ api_key: apiKey }),
        })
        if (!res.ok) {
          const detail = await res.json().catch(() => ({}))
          throw new Error((detail as { detail?: string }).detail ?? 'Invalid API key')
        }
        const { token, org_id } = await res.json() as { token: string; org_id: string }
        set({ token, orgId: org_id, apiKey })
      },

      logout: () => set({ token: null, orgId: null, apiKey: null }),
    }),
    {
      name: 'netlogic-auth',
      partialize: (s) => ({ token: s.token, orgId: s.orgId, apiKey: s.apiKey }),
    },
  ),
)
