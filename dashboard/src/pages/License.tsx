import { useState } from 'react'
import { api } from '../api/client'
import { useQueryClient } from '@tanstack/react-query'

export default function License() {
  const [key, setKey]       = useState('')
  const [error, setError]   = useState('')
  const [loading, setLoading] = useState(false)
  const qc = useQueryClient()

  async function activate(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await api.post('/license/activate', { key: key.trim() })
      qc.invalidateQueries({ queryKey: ['license'] })
      window.location.href = '/login'
    } catch (err: unknown) {
      setError((err as Error)?.message || 'Invalid license key.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-base">
      <div className="panel w-full max-w-md p-8 space-y-6 rounded-xl">
        <div className="text-center space-y-1">
          <h1 className="font-display font-bold text-2xl text-text-bright tracking-wide">NetLogic</h1>
          <p className="text-text-dim text-sm">License Required</p>
        </div>

        <p className="text-text-dim text-[13px] leading-relaxed">
          A valid license is required to access NetLogic.{' '}
          <a
            href="https://netlogic.io/pricing"
            target="_blank"
            rel="noopener noreferrer"
            className="text-accent hover:underline"
          >
            Get a license →
          </a>
        </p>

        <form onSubmit={activate} className="space-y-4">
          <div>
            <label className="text-[11px] text-text-dim uppercase tracking-wide block mb-1">
              License Key
            </label>
            <input
              className="input w-full font-mono tracking-widest"
              placeholder="NL-XXXX-XXXX-XXXX"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              autoFocus
              spellCheck={false}
            />
          </div>
          {error && <p className="text-[12px] text-critical">{error}</p>}
          <button
            type="submit"
            className="btn btn-primary w-full"
            disabled={loading || !key.trim()}
          >
            {loading ? 'Activating…' : 'Activate License'}
          </button>
        </form>
      </div>
    </div>
  )
}
