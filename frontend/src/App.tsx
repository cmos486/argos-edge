import { ReactNode } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import Layout from './components/Layout';
import ProtectedRoute from './components/ProtectedRoute';
import ToastsProvider from './components/Toasts';
import Certs from './pages/Certs';
import Dashboard from './pages/Dashboard';
import Hosts from './pages/Hosts';
import Login from './pages/Login';
import Logs from './pages/Logs';
import Rules from './pages/Rules';
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
        <Route path="/target-groups" element={<Shell><TargetGroups /></Shell>} />
        <Route path="/target-groups/:id" element={<Shell><TargetGroupDetail /></Shell>} />
        <Route path="/certs" element={<Shell><Certs /></Shell>} />
        <Route path="/logs" element={<Shell><Logs /></Shell>} />
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
