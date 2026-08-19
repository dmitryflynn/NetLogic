import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClientProvider, QueryClient } from '@tanstack/react-query'
import { ClerkProvider } from '@clerk/clerk-react'
import App from './App'
import ErrorBoundary from './components/ErrorBoundary'
import MissingConfig from './components/MissingConfig'
import { clerkAppearance } from './clerkAppearance'
import './index.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 10_000,
    },
  },
})

// Clerk publishable key (non-secret). Vite inlines it at build time.
const PUBLISHABLE_KEY = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY as string | undefined

function Root() {
  if (!PUBLISHABLE_KEY) {
    return (
      <MissingConfig message="This build has no Clerk publishable key, so sign-in cannot start. The page used to go fully black here." />
    )
  }
  return (
    <BrowserRouter>
      <ClerkProvider
        publishableKey={PUBLISHABLE_KEY}
        signInUrl="/login"
        signUpUrl="/sign-up"
        afterSignOutUrl="/login"
        appearance={clerkAppearance}
      >
        <QueryClientProvider client={queryClient}>
          <ErrorBoundary>
            <App />
          </ErrorBoundary>
        </QueryClientProvider>
      </ClerkProvider>
    </BrowserRouter>
  )
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>,
)
