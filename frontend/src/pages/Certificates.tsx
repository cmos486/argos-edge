import { useState } from 'react';
import ActiveCertsPanel from '../components/ActiveCertsPanel';
import ImportedCertsPanel from '../components/ImportedCertsPanel';

type Tab = 'active' | 'imported';

export default function Certificates() {
  const [tab, setTab] = useState<Tab>('active');
  return (
    <div className="p-6 max-w-[1400px] mx-auto">
      <h1 className="text-2xl font-semibold mb-4">Certificates</h1>

      <div className="flex items-center gap-1 mb-4 border-b border-slate-800">
        <TabButton label="Active" active={tab === 'active'} onClick={() => setTab('active')} />
        <TabButton label="Imported" active={tab === 'imported'} onClick={() => setTab('imported')} />
      </div>

      {tab === 'active' ? <ActiveCertsPanel /> : <ImportedCertsPanel />}
    </div>
  );
}

function TabButton({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`px-4 py-2 text-sm rounded-t ${
        active
          ? 'bg-slate-900 text-slate-100 border border-slate-800 border-b-slate-900'
          : 'text-slate-400 hover:text-slate-200'
      }`}
    >
      {label}
    </button>
  );
}
