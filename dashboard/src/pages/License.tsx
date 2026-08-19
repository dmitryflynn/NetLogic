import { useState } from 'react'
import { api } from '../api/client'
import { useQueryClient } from '@tanstack/react-query'
import { Brand } from '../components/Brand'

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
    <div className="min-h-screen site-bg relative flex items-center justify-center px-6">
      <div className="site-grid pointer-events-none absolute inset-0" />
      <div className="site-noise pointer-events-none absolute inset-0" />
      <div className="relative z-10 glass-strong w-full max-w-md p-9 space-y-7 rounded-2xl">
        <div className="text-center space-y-2">
          <Brand size="md" />
          <p className="text-text-dim text-[14px]">License required</p>
        </div>

        <p className="text-text-dim text-[14px] leading-relaxed">
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
            <label className="section-title block mb-2">License key</label>
            <input
              className="input w-full font-mono tracking-widest"
              placeholder="NL-XXXX-XXXX-XXXX"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              autoFocus
              spellCheck={false}
            />
          </div>
          {error && <p className="text-[13px] text-critical">{error}</p>}
          <button
            type="submit"
            className="btn btn-primary w-full"
            disabled={loading || !key.trim()}
          >
            {loading ? 'Activating…' : 'Activate license'}
          </button>
        </form>
      </div>
    </div>
  )
}
