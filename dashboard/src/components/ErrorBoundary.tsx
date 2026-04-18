import { Component, type ReactNode } from 'react'

interface Props { children: ReactNode }
interface State { error: Error | null }

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('[NetLogic] Render error:', error, info.componentStack)
  }

  render() {
    if (this.state.error) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-base">
          <div className="panel w-full max-w-lg p-8 space-y-4 rounded-xl text-center">
            <h2 className="text-text-bright font-bold text-lg">Something went wrong</h2>
            <p className="text-text-dim text-[13px]">{this.state.error.message}</p>
            <div className="flex gap-3 justify-center">
              <button
                className="btn btn-primary"
                onClick={() => this.setState({ error: null })}
              >
                Try again
              </button>
              <button
                className="btn"
                onClick={() => { window.location.href = '/' }}
              >
                Go home
              </button>
            </div>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
