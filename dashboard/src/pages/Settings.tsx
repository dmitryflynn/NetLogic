import { useEffect, useState } from 'react'
import type { UseMutationResult } from '@tanstack/react-query'
import {
  useAiSettings, useSaveAiSettings, useTestAiSettings,
  type AiSettings, type AiSettingsUpdate,
} from '../api/scan'

type SaveMut = UseMutationResult<AiSettings, Error, AiSettingsUpdate>
type TestMut = UseMutationResult<{ ok: boolean; error?: string; provider?: string; model?: string }, Error, void>

function ProviderForm({
  title, description, data, isLoading, save, test,
}: {
  title: string
  description: React.ReactNode
  data?: AiSettings
  isLoading: boolean
  save: SaveMut
  test: TestMut
}) {
  const [provider, setProvider] = useState('openrouter')
  const [apiKey,   setApiKey]   = useState('')
  const [model,    setModel]    = useState('')
  const [baseUrl,  setBaseUrl]  = useState('')
  const [saved,    setSaved]    = useState(false)
  const [testResult, setTestResult] = useState<{ ok: boolean; msg: string } | null>(null)

  useEffect(() => {
    if (!data) return
    setProvider(data.provider || 'openrouter')
    setModel(data.model || '')
    setBaseUrl(data.base_url || '')
  }, [data])

  const preset = data?.presets?.[provider]
  const isCustom = provider === 'custom'
  const isOllama = provider === 'ollama'
  function submit(e: React.FormEvent) {
    e.preventDefault()
    setSaved(false)
    setTestResult(null)
    save.mutate(
      {
        provider,
        ...(apiKey.trim() ? { api_key: apiKey.trim() } : {}),
        model: model.trim(),
        base_url: baseUrl.trim(),
      },
      { onSuccess: () => { setSaved(true); setApiKey('') } },
    )
  }

  function runTest() {
    setTestResult(null)
    test.mutate(undefined, {
      onSuccess: (r) =>
        setTestResult(r.ok
          ? { ok: true, msg: `Connected — ${r.provider} / ${r.model}` }
          : { ok: false, msg: r.error || 'Test failed' }),
      onError: (e) => setTestResult({ ok: false, msg: e.message }),
    })
  }

  if (isLoading) return <p className="text-text-dim text-[12px]">Loading…</p>

  return (
    <form onSubmit={submit} className="panel p-5 space-y-4">
      <div>
        <p className="section-title">{title}</p>
        <p className="text-text-dim text-[11px] mt-1 normal-case">{description}</p>
      </div>

      <div className="text-[11px] text-text-dim">
        Status:{' '}
        {data?.key_set ? (
          <span className="text-low">Configured · key {data.key_hint}</span>
        ) : (
          <span className="text-medium">No API key set — AI analysis will be skipped</span>
        )}
      </div>

      <div>
        <label className="section-title block mb-1.5">Provider</label>
        <select className="input w-full" value={provider} onChange={(e) => setProvider(e.target.value)}>
          {(data?.providers ?? ['openrouter']).map((p) => (
            <option key={p} value={p}>{p}</option>
          ))}
        </select>
      </div>

      {!isOllama && (
        <div>
          <label className="section-title block mb-1.5">API Key</label>
          <input
            className="input w-full"
            type="password"
            placeholder={data?.key_set ? `•••••• (${data.key_hint}) — leave blank to keep` : 'Paste your API key'}
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            autoComplete="off"
          />
        </div>
      )}

      <div>
        <label className="section-title block mb-1.5">
          Model {preset && <span className="text-text-dim normal-case">— default: {preset.model}</span>}
        </label>
        <input
          className="input w-full"
          placeholder={preset?.model || 'model name'}
          value={model}
          onChange={(e) => setModel(e.target.value)}
        />
      </div>

      {(isCustom || baseUrl) && (
        <div>
          <label className="section-title block mb-1.5">
            Base URL {isCustom && <span className="text-critical">*</span>}
            {preset && <span className="text-text-dim normal-case"> — default: {preset.base_url}</span>}
          </label>
          <input
            className="input w-full"
            placeholder={preset?.base_url || 'https://…/v1'}
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
          />
        </div>
      )}

      {save.error && <p className="text-critical text-[11px]">{save.error.message}</p>}
      {saved && <p className="text-low text-[11px]">Saved.</p>}
      {testResult && (
        <p className={`text-[11px] ${testResult.ok ? 'text-low' : 'text-critical'}`}>
          {testResult.ok ? '✓ ' : '✗ '}{testResult.msg}
        </p>
      )}

      <div className="flex gap-2 pt-1">
        <button type="submit" className="btn btn-primary" disabled={save.isPending}>
          {save.isPending ? 'Saving…' : 'Save'}
        </button>
        <button
          type="button"
          className="btn"
          onClick={runTest}
          disabled={test.isPending || !data?.key_set}
          title={data?.key_set ? 'Send a tiny request to verify the key works' : 'Save a key first'}
        >
          {test.isPending ? 'Testing…' : 'Test connection'}
        </button>
      </div>
    </form>
  )
}

function AiSection() {
  const q = useAiSettings()
  const save = useSaveAiSettings()
  const test = useTestAiSettings()
  return (
    <ProviderForm
      title="AI Analysis"
      description="Model that writes the human-readable report (executive summary, attack chains, remediation)."
      data={q.data}
      isLoading={q.isLoading}
      save={save}
      test={test}
    />
  )
}

export default function Settings() {
  return (
    <div className="max-w-2xl mx-auto px-6 py-6 space-y-6">
      <div>
        <h2 className="font-display font-bold text-lg text-text-bright tracking-wide">Settings</h2>
        <p className="text-text-dim text-[12px] mt-1">
          Configure the AI provider. The key is stored on the server and never displayed again.
        </p>
      </div>
      <AiSection />
    </div>
  )
}
