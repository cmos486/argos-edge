import { FormEvent, useCallback, useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { AlertTriangle, ArrowLeft, Plus, Power, Trash2 } from 'lucide-react';
import {
  ApiError,
  CRSRule,
  HostSecurityBundle,
  RateLimitKey,
  WAFCustomRule,
  WAFExclusion,
  WAFMode,
  api,
} from '../api/client';
import Modal from '../components/Modal';
import { useToasts } from '../components/toastsContext';

export default function HostSecurity() {
  const { id } = useParams();
  const hostId = Number(id);
  const toasts = useToasts();
  const navigate = useNavigate();
  const [bundle, setBundle] = useState<HostSecurityBundle | null>(null);
  const [crs, setCRS] = useState<CRSRule[]>([]);
  const [saving, setSaving] = useState(false);
  const [excModalOpen, setExcModalOpen] = useState(false);
  const [crModalOpen, setCRModalOpen] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const b = await api.getHostSecurity(hostId);
      setBundle(b);
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'load failed', 'error');
    }
  }, [hostId, toasts]);

  useEffect(() => {
    if (!Number.isFinite(hostId) || hostId <= 0) return;
    refresh();
    api.crsRules().then(setCRS).catch(() => {});
  }, [hostId, refresh]);

  if (!bundle) {
    return <div className="p-6 text-slate-400">loading...</div>;
  }

  function patch(partial: Partial<HostSecurityBundle>) {
    setBundle({ ...bundle!, ...partial });
  }

  async function save() {
    if (!bundle) return;
    setSaving(true);
    try {
      // The PUT returns the freshly-persisted core so we can snap the
      // local bundle to it immediately; refresh() then re-pulls the
      // full bundle (with exclusions + custom_rules) to make sure the
      // view matches what the server actually has.
      const persisted = await api.updateHostSecurity(hostId, {
        waf_enabled: bundle.waf_enabled,
        waf_mode: bundle.waf_mode,
        waf_paranoia: bundle.waf_paranoia,
        waf_block_status: bundle.waf_block_status,
        waf_block_body: bundle.waf_block_body,
        rate_limit_enabled: bundle.rate_limit_enabled,
        rate_limit_requests: bundle.rate_limit_requests,
        rate_limit_window_seconds: bundle.rate_limit_window_seconds,
        rate_limit_key: bundle.rate_limit_key,
        rate_limit_header_name: bundle.rate_limit_header_name,
        rate_limit_status: bundle.rate_limit_status,
      });
      setBundle({ ...bundle, ...persisted });
      toasts.push('security saved', 'success');
      await refresh();
      navigate('/security');
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'save failed', 'error');
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-4">
      <Link
        to="/hosts"
        className="inline-flex items-center gap-1 text-slate-400 hover:text-slate-200 text-sm"
      >
        <ArrowLeft className="w-4 h-4" />
        Hosts
      </Link>
      <h1 className="text-2xl font-semibold">Security</h1>

      <Card title="WAF">
        <label className="flex items-center gap-2 mb-3">
          <input
            type="checkbox"
            checked={bundle.waf_enabled}
            onChange={(e) => patch({ waf_enabled: e.target.checked })}
            className="w-4 h-4 accent-sky-600"
          />
          <span>Enabled</span>
        </label>

        {bundle.waf_enabled && (
          <div className="space-y-3 text-sm">
            {bundle.waf_mode === 'detect' && (
              <div className="px-3 py-2 rounded bg-amber-950/40 border border-amber-900 text-amber-300 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" />
                Detection only. Malicious requests are logged but NOT
                blocked. Switch to <b>block</b> after tuning exclusions.
              </div>
            )}

            <div className="flex gap-4">
              {(['detect', 'block'] as WAFMode[]).map((m) => (
                <label key={m} className="flex items-center gap-2">
                  <input
                    type="radio"
                    checked={bundle.waf_mode === m}
                    onChange={() => patch({ waf_mode: m })}
                    className="accent-sky-600"
                  />
                  <span className={
                    m === 'block'
                      ? 'px-2 py-0.5 rounded bg-red-900 text-red-200 text-xs'
                      : 'px-2 py-0.5 rounded bg-amber-900 text-amber-200 text-xs'
                  }>
                    {m}
                  </span>
                </label>
              ))}
            </div>

            <div>
              <label className="block text-slate-300 mb-1">Paranoia level</label>
              <select
                value={bundle.waf_paranoia}
                onChange={(e) => patch({ waf_paranoia: Number(e.target.value) })}
                className="px-3 py-1.5 rounded bg-slate-800 border border-slate-700"
              >
                <option value={1}>1 — basic OWASP rules (default)</option>
                <option value={2}>2 — stricter; more false positives</option>
                <option value={3}>3 — aggressive; expect tuning</option>
                <option value={4}>4 — highest; serious tuning required</option>
              </select>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-slate-300 mb-1">Block status</label>
                <input
                  type="number"
                  min={100}
                  max={599}
                  value={bundle.waf_block_status}
                  onChange={(e) => patch({ waf_block_status: Number(e.target.value) })}
                  className="w-full px-3 py-1.5 rounded bg-slate-800 border border-slate-700 font-mono"
                />
                <p className="text-xs text-slate-500 mt-1">
                  Note: Coraza defaults to 403 on block; this field becomes
                  effective once a custom SecRule overrides it.
                </p>
              </div>
              <div>
                <label className="block text-slate-300 mb-1">Block body (optional)</label>
                <input
                  type="text"
                  value={bundle.waf_block_body}
                  onChange={(e) => patch({ waf_block_body: e.target.value })}
                  className="w-full px-3 py-1.5 rounded bg-slate-800 border border-slate-700"
                />
              </div>
            </div>
          </div>
        )}
      </Card>

      <Card title="Rate limiting">
        <label className="flex items-center gap-2 mb-3">
          <input
            type="checkbox"
            checked={bundle.rate_limit_enabled}
            onChange={(e) => patch({ rate_limit_enabled: e.target.checked })}
            className="w-4 h-4 accent-sky-600"
          />
          <span>Enabled</span>
        </label>
        {bundle.rate_limit_enabled && (
          <div className="grid grid-cols-4 gap-3 text-sm">
            <div>
              <label className="block text-slate-300 mb-1">Requests</label>
              <input
                type="number"
                min={1}
                value={bundle.rate_limit_requests}
                onChange={(e) => patch({ rate_limit_requests: Number(e.target.value) })}
                className="w-full px-3 py-1.5 rounded bg-slate-800 border border-slate-700 font-mono"
              />
            </div>
            <div>
              <label className="block text-slate-300 mb-1">Window (s)</label>
              <input
                type="number"
                min={1}
                max={3600}
                value={bundle.rate_limit_window_seconds}
                onChange={(e) => patch({ rate_limit_window_seconds: Number(e.target.value) })}
                className="w-full px-3 py-1.5 rounded bg-slate-800 border border-slate-700 font-mono"
              />
            </div>
            <div>
              <label className="block text-slate-300 mb-1">Key</label>
              <select
                value={bundle.rate_limit_key}
                onChange={(e) => patch({ rate_limit_key: e.target.value as RateLimitKey })}
                className="w-full px-3 py-1.5 rounded bg-slate-800 border border-slate-700"
              >
                <option value="ip">IP</option>
                <option value="header">Header</option>
                <option value="global">Global</option>
              </select>
            </div>
            {bundle.rate_limit_key === 'header' ? (
              <div>
                <label className="block text-slate-300 mb-1">Header name</label>
                <input
                  type="text"
                  value={bundle.rate_limit_header_name}
                  onChange={(e) => patch({ rate_limit_header_name: e.target.value })}
                  className="w-full px-3 py-1.5 rounded bg-slate-800 border border-slate-700 font-mono"
                  placeholder="X-Client-ID"
                />
              </div>
            ) : (
              <div>
                <label className="block text-slate-300 mb-1">Status</label>
                <input
                  type="number"
                  min={100}
                  max={599}
                  value={bundle.rate_limit_status}
                  onChange={(e) => patch({ rate_limit_status: Number(e.target.value) })}
                  className="w-full px-3 py-1.5 rounded bg-slate-800 border border-slate-700 font-mono"
                />
                <p className="text-xs text-slate-500 mt-1">caddy-ratelimit returns 429; UI hint only</p>
              </div>
            )}
          </div>
        )}
      </Card>

      <Card
        title="Exclusions"
        action={
          <button
            type="button"
            onClick={() => setExcModalOpen(true)}
            className="flex items-center gap-1 px-2 py-1 rounded bg-sky-600 hover:bg-sky-500 text-sm"
          >
            <Plus className="w-4 h-4" /> Add exclusion
          </button>
        }
      >
        <ExclusionsTable
          hostId={hostId}
          rows={bundle.exclusions}
          onChanged={refresh}
        />
      </Card>

      <Card
        title="Custom rules"
        action={
          <button
            type="button"
            onClick={() => setCRModalOpen(true)}
            className="flex items-center gap-1 px-2 py-1 rounded bg-sky-600 hover:bg-sky-500 text-sm"
          >
            <Plus className="w-4 h-4" /> Add custom rule
          </button>
        }
      >
        <div className="px-3 py-2 rounded bg-red-950/40 border border-red-900 text-red-300 text-xs mb-3 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4" />
          Advanced. Syntax errors can break the WAF for this host. Use at your own risk.
        </div>
        <CustomRulesTable hostId={hostId} rows={bundle.custom_rules} onChanged={refresh} />
      </Card>

      <div className="pt-2">
        <button
          type="button"
          onClick={save}
          disabled={saving}
          className="px-4 py-2 rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 text-sm font-medium"
        >
          {saving ? 'saving...' : 'Save security config'}
        </button>
      </div>

      <ExclusionModal
        open={excModalOpen}
        hostId={hostId}
        crs={crs}
        onClose={() => setExcModalOpen(false)}
        onSaved={async () => {
          setExcModalOpen(false);
          await refresh();
        }}
      />
      <CustomRuleModal
        open={crModalOpen}
        hostId={hostId}
        onClose={() => setCRModalOpen(false)}
        onSaved={async () => {
          setCRModalOpen(false);
          await refresh();
        }}
      />
    </div>
  );
}

function Card({
  title,
  action,
  children,
}: {
  title: string;
  action?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="bg-slate-900 border border-slate-800 rounded-lg p-4">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-lg font-semibold">{title}</h2>
        {action}
      </div>
      {children}
    </section>
  );
}

function ExclusionsTable({
  hostId,
  rows,
  onChanged,
}: {
  hostId: number;
  rows: WAFExclusion[];
  onChanged: () => Promise<void> | void;
}) {
  const toasts = useToasts();
  async function onToggle(ex: WAFExclusion) {
    try {
      await api.toggleExclusion(hostId, ex.id);
      await onChanged();
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'toggle failed', 'error');
    }
  }
  async function onDelete(ex: WAFExclusion) {
    if (!window.confirm(`Delete exclusion #${ex.id}?`)) return;
    try {
      await api.deleteExclusion(hostId, ex.id);
      toasts.push('exclusion removed', 'success');
      await onChanged();
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'delete failed', 'error');
    }
  }
  if (rows.length === 0) {
    return <p className="text-sm text-slate-500">No exclusions yet.</p>;
  }
  return (
    <table className="w-full text-sm">
      <thead className="text-slate-400 uppercase text-xs tracking-wide">
        <tr>
          <th className="text-left px-2 py-1">CRS Rule ID</th>
          <th className="text-left px-2 py-1">Path</th>
          <th className="text-left px-2 py-1">Reason</th>
          <th className="text-left px-2 py-1">Enabled</th>
          <th className="text-right px-2 py-1">Actions</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((ex) => (
          <tr key={ex.id} className="border-t border-slate-800">
            <td className="px-2 py-1 font-mono">{ex.crs_rule_id}</td>
            <td className="px-2 py-1 font-mono text-slate-300">{ex.path_pattern || <i className="text-slate-500">global</i>}</td>
            <td className="px-2 py-1 text-slate-400">{ex.reason}</td>
            <td className="px-2 py-1">
              <span
                className={`text-xs px-2 py-0.5 rounded ${
                  ex.enabled ? 'bg-emerald-900 text-emerald-200' : 'bg-slate-800 text-slate-400'
                }`}
              >
                {ex.enabled ? 'on' : 'off'}
              </span>
            </td>
            <td className="px-2 py-1 text-right">
              <button type="button" onClick={() => onToggle(ex)} className="p-1 rounded border border-slate-700 hover:bg-slate-800 mr-1">
                <Power className="w-3 h-3" />
              </button>
              <button type="button" onClick={() => onDelete(ex)} className="p-1 rounded border border-slate-700 hover:bg-slate-800 text-red-400">
                <Trash2 className="w-3 h-3" />
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function CustomRulesTable({
  hostId,
  rows,
  onChanged,
}: {
  hostId: number;
  rows: WAFCustomRule[];
  onChanged: () => Promise<void> | void;
}) {
  const toasts = useToasts();
  async function onToggle(r: WAFCustomRule) {
    try {
      await api.toggleCustomRule(hostId, r.id);
      await onChanged();
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'toggle failed', 'error');
    }
  }
  async function onDelete(r: WAFCustomRule) {
    if (!window.confirm(`Delete custom rule "${r.name}"?`)) return;
    try {
      await api.deleteCustomRule(hostId, r.id);
      toasts.push('custom rule deleted', 'success');
      await onChanged();
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'delete failed', 'error');
    }
  }
  if (rows.length === 0) return <p className="text-sm text-slate-500">No custom rules yet.</p>;
  return (
    <table className="w-full text-sm">
      <thead className="text-slate-400 uppercase text-xs tracking-wide">
        <tr>
          <th className="text-left px-2 py-1">Name</th>
          <th className="text-left px-2 py-1">Enabled</th>
          <th className="text-right px-2 py-1">Actions</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.id} className="border-t border-slate-800">
            <td className="px-2 py-1">{r.name || <i className="text-slate-500">unnamed</i>}</td>
            <td className="px-2 py-1">
              <span
                className={`text-xs px-2 py-0.5 rounded ${
                  r.enabled ? 'bg-emerald-900 text-emerald-200' : 'bg-slate-800 text-slate-400'
                }`}
              >
                {r.enabled ? 'on' : 'off'}
              </span>
            </td>
            <td className="px-2 py-1 text-right">
              <button type="button" onClick={() => onToggle(r)} className="p-1 rounded border border-slate-700 hover:bg-slate-800 mr-1">
                <Power className="w-3 h-3" />
              </button>
              <button type="button" onClick={() => onDelete(r)} className="p-1 rounded border border-slate-700 hover:bg-slate-800 text-red-400">
                <Trash2 className="w-3 h-3" />
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ExclusionModal({
  open,
  hostId,
  crs,
  onClose,
  onSaved,
}: {
  open: boolean;
  hostId: number;
  crs: CRSRule[];
  onClose: () => void;
  onSaved: () => Promise<void> | void;
}) {
  const [ruleID, setRuleID] = useState('');
  const [path, setPath] = useState('');
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const match = crs.find((r) => String(r.id) === ruleID.trim());

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setSubmitting(true);
    setErr(null);
    try {
      await api.createExclusion(hostId, {
        crs_rule_id: Number(ruleID),
        path_pattern: path,
        reason,
      });
      setRuleID('');
      setPath('');
      setReason('');
      await onSaved();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'create failed');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Modal open={open} title="Add exclusion" onClose={onClose}>
      <form onSubmit={onSubmit} className="space-y-3 text-sm">
        <div>
          <label className="block text-slate-300 mb-1">CRS Rule ID</label>
          <input
            type="number"
            required
            value={ruleID}
            onChange={(e) => setRuleID(e.target.value)}
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
            placeholder="942100"
            list="crs-list"
          />
          <datalist id="crs-list">
            {crs.slice(0, 500).map((r) => (
              <option key={r.id} value={r.id}>{`${r.id} — ${r.description}`}</option>
            ))}
          </datalist>
          {match && (
            <p className="mt-1 text-xs text-slate-400">
              <span className="font-mono">{match.id}</span> [{match.category}, PL{match.paranoia}]: {match.description}
            </p>
          )}
        </div>
        <div>
          <label className="block text-slate-300 mb-1">Path (optional, leave empty for global)</label>
          <input
            type="text"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="/api/upload/*"
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
          />
        </div>
        <div>
          <label className="block text-slate-300 mb-1">Reason</label>
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={2}
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700"
          />
        </div>
        {err && (
          <div className="px-3 py-2 rounded bg-red-950/40 border border-red-900 text-red-300">
            {err}
          </div>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className="px-3 py-1.5 rounded border border-slate-700 hover:bg-slate-800">
            Cancel
          </button>
          <button
            type="submit"
            disabled={submitting}
            className="px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 font-medium"
          >
            {submitting ? 'adding...' : 'Add'}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function CustomRuleModal({
  open,
  hostId,
  onClose,
  onSaved,
}: {
  open: boolean;
  hostId: number;
  onClose: () => void;
  onSaved: () => Promise<void> | void;
}) {
  const [name, setName] = useState('');
  const [secrule, setSecrule] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setSubmitting(true);
    setErr(null);
    try {
      await api.createCustomRule(hostId, { name, secrule });
      setName('');
      setSecrule('');
      await onSaved();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'create failed');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Modal open={open} title="Add custom SecRule" onClose={onClose}>
      <form onSubmit={onSubmit} className="space-y-3 text-sm">
        <div>
          <label className="block text-slate-300 mb-1">Name</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700"
          />
        </div>
        <div>
          <label className="block text-slate-300 mb-1">SecRule / SecAction</label>
          <textarea
            required
            value={secrule}
            onChange={(e) => setSecrule(e.target.value)}
            rows={8}
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono text-xs"
            placeholder={`SecRule REQUEST_HEADERS:User-Agent "@contains test-blocked-ua" "id:100001,phase:1,deny,status:418,log,msg:'custom UA block'"`}
          />
          <p className="text-xs text-slate-500 mt-1">
            ID must be in 100000-899999. Submit validates syntax before persisting.
          </p>
        </div>
        {err && (
          <div className="px-3 py-2 rounded bg-red-950/40 border border-red-900 text-red-300">
            {err}
          </div>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className="px-3 py-1.5 rounded border border-slate-700 hover:bg-slate-800">
            Cancel
          </button>
          <button
            type="submit"
            disabled={submitting}
            className="px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 font-medium"
          >
            {submitting ? 'adding...' : 'Add'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
