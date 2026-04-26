import { Component, ErrorInfo, ReactNode, Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { Loader2, TriangleAlert } from 'lucide-react';
import Layout from './components/Layout';
import ProtectedRoute from './components/ProtectedRoute';
import ToastsProvider from './components/Toasts';
// Login stays eager: it's the first paint after hydration when the
// user has no session cookie. Lazy-loading would add a spinner flash
// before the form appears, which is worse UX than shipping ~8 KiB
// extra in the initial bundle.
import Login from './pages/Login';

// Everything else is code-split by route. React.lazy returns a
// component whose module is fetched on first render; Suspense catches
// the pending promise and renders <RouteFallback/> in the meantime.
// The chunk filename is derived from the import path; the generated
// hash changes only when THIS page's content changes, which plays
// well with long-term HTTP caching for unchanged pages.
const AppSec = lazy(() => import('./pages/AppSec'));
const Certificates = lazy(() => import('./pages/Certificates'));
const Dashboard = lazy(() => import('./pages/Dashboard'));
const Hosts = lazy(() => import('./pages/Hosts'));
const HostSecurity = lazy(() => import('./pages/HostSecurity'));
const Backup = lazy(() => import('./pages/Backup'));
const Logs = lazy(() => import('./pages/Logs'));
const Notifications = lazy(() => import('./pages/Notifications'));
const Rules = lazy(() => import('./pages/Rules'));
const System = lazy(() => import('./pages/System'));
const Threats = lazy(() => import('./pages/Threats'));
const SecurityOverviewPage = lazy(() => import('./pages/SecurityOverview'));
const SecurityPage = lazy(() => import('./pages/Security'));
const Settings = lazy(() => import('./pages/Settings'));
const TargetGroupDetail = lazy(() => import('./pages/TargetGroupDetail'));
const TargetGroups = lazy(() => import('./pages/TargetGroups'));

export default function App() {
  return (
    <ToastsProvider>
      <ChunkErrorBoundary>
        <Suspense fallback={<RouteFallback />}>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/" element={<Shell><Dashboard /></Shell>} />
            <Route path="/hosts" element={<Shell><Hosts /></Shell>} />
            <Route path="/hosts/:id/rules" element={<Shell><Rules /></Shell>} />
            <Route path="/hosts/:id/security" element={<Shell><HostSecurity /></Shell>} />
            <Route path="/security" element={<Shell><SecurityPage /></Shell>} />
            {/*
              v1.3.24 split: /security is now the global security
              tabs (Banned IPs / Whitelist / Activity); the
              host-WAF overview moved to /security/hosts. The new
              page surfaces a session-dismissable banner pointing
              bookmarks at /security/hosts so the move is
              discoverable for operators who land on the old URL.
            */}
            <Route path="/security/hosts" element={<Shell><SecurityOverviewPage /></Shell>} />
            <Route path="/threats" element={<Shell><Threats /></Shell>} />
            <Route
              path="/appsec"
              element={
                <ProtectedRoute>
                  {(user) => (
                    <Layout username={user.username}>
                      <AppSec username={user.username} />
                    </Layout>
                  )}
                </ProtectedRoute>
              }
            />
            <Route path="/target-groups" element={<Shell><TargetGroups /></Shell>} />
            <Route path="/target-groups/:id" element={<Shell><TargetGroupDetail /></Shell>} />
            <Route path="/certificates" element={<Shell><Certificates /></Shell>} />
            {/* v1.0 compatibility: external links to /certs continue to work. */}
            <Route path="/certs" element={<Navigate to="/certificates" replace />} />
            <Route path="/logs" element={<Shell><Logs /></Shell>} />
            <Route path="/notifications" element={<Shell><Notifications /></Shell>} />
            <Route path="/backup" element={<Shell><Backup /></Shell>} />
            <Route path="/system" element={<Shell><System /></Shell>} />
            <Route path="/settings" element={<Shell><Settings /></Shell>} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Suspense>
      </ChunkErrorBoundary>
    </ToastsProvider>
  );
}

function Shell({ children }: { children: ReactNode }) {
  return (
    <ProtectedRoute>
      {(user) => <Layout username={user.username}>{children}</Layout>}
    </ProtectedRoute>
  );
}

// RouteFallback is the in-flight indicator rendered while a lazy
// chunk downloads. Min-height matches a typical dashboard section
// so the page does not jump on chunk arrival; the spinner is small
// enough to feel instant on a warm cache.
function RouteFallback() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 text-slate-400">
      <Loader2 className="w-5 h-5 animate-spin" />
    </div>
  );
}

// ChunkErrorBoundary catches the specific failure mode where a lazy
// chunk cannot load -- typical causes: panel was redeployed mid-
// session (hashed asset URL now 404s), a flaky network blip, or a
// corporate proxy caching an old index.html. The generic React
// error overlay is unhelpful in those cases; offering a one-click
// reload gets the user back onto the fresh bundle.
//
// We deliberately do NOT retry the import automatically. An infinite
// retry loop on a genuinely missing chunk would hammer the server
// and pin the CPU; a visible "Reload" is a honest escape hatch.
interface BoundaryState {
  failed: boolean;
  err?: Error;
}
class ChunkErrorBoundary extends Component<{ children: ReactNode }, BoundaryState> {
  override state: BoundaryState = { failed: false };

  static getDerivedStateFromError(err: Error): BoundaryState {
    return { failed: true, err };
  }

  override componentDidCatch(err: Error, info: ErrorInfo) {
    // One-line console hint so the devtools network tab is actionable.
    // We do NOT send this server-side -- no error reporting hook in
    // the panel, and the user's reload is the remediation.
    console.error('chunk load failure', err, info.componentStack);
  }

  override render() {
    if (!this.state.failed) return this.props.children;
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950 text-slate-100 p-6">
        <div className="max-w-sm bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-3 text-center">
          <TriangleAlert className="w-8 h-8 mx-auto text-amber-400" />
          <h1 className="text-lg font-semibold">Failed to load page</h1>
          <p className="text-sm text-slate-400">
            A piece of the panel could not be fetched. This usually means a
            new version has been deployed since you loaded this page.
          </p>
          <button
            type="button"
            onClick={() => window.location.reload()}
            className="w-full py-2 rounded bg-sky-600 hover:bg-sky-500 font-medium"
          >
            Reload
          </button>
          {this.state.err && (
            <div className="text-xs text-slate-500 font-mono break-all text-left">
              {this.state.err.message}
            </div>
          )}
        </div>
      </div>
    );
  }
}
