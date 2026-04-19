import { ReactNode } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import Layout from './components/Layout';
import ProtectedRoute from './components/ProtectedRoute';
import ToastsProvider from './components/Toasts';
import Certs from './pages/Certs';
import Dashboard from './pages/Dashboard';
import Hosts from './pages/Hosts';
import HostSecurity from './pages/HostSecurity';
import Login from './pages/Login';
import Backup from './pages/Backup';
import Logs from './pages/Logs';
import Notifications from './pages/Notifications';
import Rules from './pages/Rules';
import SecurityOverviewPage from './pages/SecurityOverview';
import Settings from './pages/Settings';
import TargetGroupDetail from './pages/TargetGroupDetail';
import TargetGroups from './pages/TargetGroups';

export default function App() {
  return (
    <ToastsProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<Shell><Dashboard /></Shell>} />
        <Route path="/hosts" element={<Shell><Hosts /></Shell>} />
        <Route path="/hosts/:id/rules" element={<Shell><Rules /></Shell>} />
        <Route path="/hosts/:id/security" element={<Shell><HostSecurity /></Shell>} />
        <Route path="/security" element={<Shell><SecurityOverviewPage /></Shell>} />
        <Route path="/target-groups" element={<Shell><TargetGroups /></Shell>} />
        <Route path="/target-groups/:id" element={<Shell><TargetGroupDetail /></Shell>} />
        <Route path="/certs" element={<Shell><Certs /></Shell>} />
        <Route path="/logs" element={<Shell><Logs /></Shell>} />
        <Route path="/notifications" element={<Shell><Notifications /></Shell>} />
        <Route path="/backup" element={<Shell><Backup /></Shell>} />
        <Route path="/settings" element={<Shell><Settings /></Shell>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
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
