/**
 * Thin fetch wrapper that attaches the live Clerk session token and handles
 * errors. All API functions return typed data or throw an Error with a message.
 */

const BASE = (import.meta.env.VITE_API_URL ?? '') + '/v1'

// Clerk attaches a global `window.Clerk` once ClerkProvider mounts. We read the
// current session token per request (Clerk auto-refreshes it), so there is no
// long-lived credential stored anywhere in the app.
declare global {
  interface Window {
    Clerk?: { session?: { getToken: () => Promise<string | null> } }
  }
}

async function getToken(): Promise<string | null> {
  try {
    const session = window.Clerk?.session
    return session ? await session.getToken() : null
  } catch {
    return null
  }
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const token = await getToken()
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (token) headers['Authorization'] = `Bearer ${token}`

  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })

  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    const d = (body as { detail?: unknown }).detail
    const msg =
      typeof d === 'string'
        ? d
        : Array.isArray(d)
          ? d.map((e: { msg?: string }) => e.msg ?? JSON.stringify(e)).join('; ')
          : `HTTP ${res.status}`
    throw new Error(msg)
  }

  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

export const api = {
  get:    <T>(path: string)                  => request<T>('GET',    path),
  post:   <T>(path: string, body?: unknown)  => request<T>('POST',   path, body),
  delete: <T>(path: string)                  => request<T>('DELETE', path),
}

/** Raw fetch for SSE streams (needs auth header, EventSource doesn't support it). */
export async function streamFetch(path: string, signal: AbortSignal): Promise<Response> {
  const token = await getToken()
  const headers: Record<string, string> = {}
  if (token) headers['Authorization'] = `Bearer ${token}`
  return fetch(`${BASE}${path}`, { headers, signal })
}
