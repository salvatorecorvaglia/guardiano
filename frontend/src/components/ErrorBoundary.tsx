import { Component, type ErrorInfo, type ReactNode } from "react";

/** Contains render errors to one page instead of blanking the whole app. Change resetKey to recover. */
export default class ErrorBoundary extends Component<{ children: ReactNode; resetKey?: unknown }, { error: Error | null }> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Unhandled render error", error, info.componentStack);
  }

  componentDidUpdate(prev: { resetKey?: unknown }) {
    if (this.state.error && prev.resetKey !== this.props.resetKey) this.setState({ error: null });
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="card mx-auto mt-10 max-w-lg p-6 text-center" role="alert">
        <p className="font-medium">Something went wrong displaying this page.</p>
        <p className="mt-1 text-sm text-ink2">{this.state.error.message}</p>
        <button className="btn-secondary mt-4" onClick={() => this.setState({ error: null })}>
          Try again
        </button>
      </div>
    );
  }
}
