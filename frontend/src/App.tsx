import { ReactNode } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import Layout from './components/Layout';
import ProtectedRoute from './components/ProtectedRoute';
import ToastsProvider from './components/Toasts';
import Certs from './pages/Certs';
import Dashboard from './pages/Dashboard';
import Hosts from './pages/Hosts';
import Login from './pages/Login';

export default function App() {
  return (
    <ToastsProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<Shell><Dashboard /></Shell>} />
        <Route path="/hosts" element={<Shell><Hosts /></Shell>} />
        <Route path="/certs" element={<Shell><Certs /></Shell>} />
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
