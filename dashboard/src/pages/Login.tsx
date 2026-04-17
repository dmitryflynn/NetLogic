import { useState, FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '../store/auth'

export default function Login() {
  const [key, setKey]   = useState('')
  const [err, setErr]   = useState('')
  const [busy, setBusy] = useState(false)
  const login           = useAuthStore((s) => s.login)
  const nav             = useNavigate()

  async function submit(e: FormEvent) {
    e.preventDefault()
    setErr('')
    setBusy(true)
    try {
      await login(key.trim())
      nav('/', { replace: true })
    } catch (ex) {
      setErr((ex as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="min-h-full flex items-center justify-center bg-base">
      <div className="w-full max-w-sm panel p-8 space-y-6">
        {/* Logo */}
        <div className="text-center space-y-1">
          <p className="font-display font-bold text-xl text-text-bright tracking-widest">
            NET<span className="text-accent">LOGIC</span>
          </p>
          <p className="text-text-dim text-[11px]">Attack Surface Intelligence</p>
        </div>

        <form onSubmit={submit} className="space-y-4">
          <div>
            <label className="section-title block mb-1.5">API Key</label>
            <input
              className="input"
              type="password"
              placeholder="Enter your API key…"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              required
              autoFocus
            />
          </div>

          {err && (
            <p className="text-critical text-[11px] bg-critical/10 border border-critical/30 rounded px-3 py-2">
              {err}
            </p>
          )}

          <button
            type="submit"
            disabled={busy || !key.trim()}
            className="btn btn-primary w-full justify-center py-2 disabled:opacity-40"
          >
            {busy ? 'Authenticating…' : 'Sign In'}
          </button>
        </form>

        <p className="text-center text-text-dim text-[10px]">
          For authorized use only
        </p>
      </div>
    </div>
  )
}
