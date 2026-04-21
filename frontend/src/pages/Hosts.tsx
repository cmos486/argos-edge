import { FormEvent, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { FileText, ListOrdered, Lock, Pencil, Plus, Power, Shield, ShieldAlert, Trash2, Unlock } from 'lucide-react';
import {
  ApiError,
  DNSProvider,
  Host,
  HostInput,
  TLSChallenge,
  TLSMode,
  TargetGroup,
  api,
} from '../api/client';
import ManualCertSection from '../components/ManualCertSection';
import Modal from '../components/Modal';
import TargetGroupForm from '../components/TargetGroupForm';
import {
  TargetGroupFormValue,
  emptyTargetGroupForm,
} from '../components/targetGroupFormValue';
import { useToasts } from '../components/toastsContext';

type HostFormState = {
  id?: number;
  domain: string;
  tls_mode: TLSMode;
  tls_email: string;
  tls_acme_ca_url: string;
  tls_challenge: TLSChallenge;
  // v1.3+: which DNS-01 provider the reconciler reads credentials
  // from when tls_challenge='dns'. Default 'cloudflare' preserves
  // the pre-v1.3 single-provider behaviour.
  tls_dns_provider: string;
  // target group selection: either "existing:{id}" or "inline"
  tgChoice: string;
  tgInline: TargetGroupFormValue;
};

const INLINE_CHOICE = 'inline';

function emptyHostForm(): HostFormState {
  return {
    domain: '',
    tls_mode: 'auto',
    tls_email: '',
    tls_acme_ca_url: '',
    tls_challenge: 'dns',
    tls_dns_provider: 'cloudflare',
    tgChoice: '',
    tgInline: emptyTargetGroupForm(),
  };
}

export default function Hosts() {
  const toasts = useToasts();
  const [hosts, setHosts] = useState<Host[] | null>(null);
  const [tgs, setTgs] = useState<TargetGroup[]>([]);
  const [dnsProviders, setDnsProviders] = useState<DNSProvider[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [form, setForm] = useState<HostFormState>(emptyHostForm());
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  async function refresh() {
    try {
      const [hostList, tgList, providers] = await Promise.all([
        api.listHosts(),
        api.listTargetGroups(),
        // DNS providers catalogue drives the host-form provider
        // dropdown. A soft failure (endpoint unreachable on an
        // upgrade-in-progress panel) should not block the rest of
        // the page — default to an empty list and the dropdown
        // falls back to its "no providers" amber warning.
        api.listDNSProviders().catch(() => [] as DNSProvider[]),
      ]);
      setHosts(hostList);
      setTgs(tgList);
      setDnsProviders(providers);
      setLoadError(null);
    } catch (err) {
      setLoadError(err instanceof ApiError ? err.message : 'load failed');
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  const enabledProviders = useMemo(
    () => dnsProviders.filter((p) => p.enabled && p.configured),
    [dnsProviders],
  );

  function openCreate() {
    const next = emptyHostForm();
    if (tgs.length > 0) {
      next.tgChoice = String(tgs[0]!.id);
    } else {
      next.tgChoice = INLINE_CHOICE;
    }
    setForm(next);
    setFormError(null);
    setModalOpen(true);
  }

  function openEdit(h: Host) {
    setForm({
      id: h.id,
      domain: h.domain,
      tls_mode: h.tls_mode,
      tls_email: h.tls_email,
      tls_acme_ca_url: h.tls_acme_ca_url ?? '',
      tls_challenge: (h.tls_challenge as TLSChallenge | undefined) ?? 'dns',
      tls_dns_provider: h.tls_dns_provider || 'cloudflare',
      tgChoice: String(h.target_group_id),
      tgInline: emptyTargetGroupForm(),
    });
    setFormError(null);
    setModalOpen(true);
  }

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setSubmitting(true);
    setFormError(null);

    // DNS-01 needs a concrete provider. Block submit rather than let
    // the backend reject with a cryptic 400 — the dropdown already
    // surfaces "no providers enabled" as an amber warning, but the
    // user might still click Save.
    if (form.tls_mode === 'auto' && form.tls_challenge === 'dns') {
      if (!form.tls_dns_provider) {
        setFormError(
          'pick a DNS provider (or configure one in Settings → DNS providers first)',
        );
        setSubmitting(false);
        return;
      }
    }

    try {
      const base: HostInput = {
        domain: form.domain,
        tls_mode: form.tls_mode,
        tls_email: form.tls_email,
        tls_acme_ca_url: form.tls_acme_ca_url.trim(),
        tls_challenge: form.tls_challenge,
        tls_dns_provider: form.tls_dns_provider || 'cloudflare',
      };

      if (form.tgChoice === INLINE_CHOICE) {
        if (form.id) {
          setFormError('inline target_group is not supported on update; pick an existing one');
          setSubmitting(false);
          return;
        }
        base.target_group = { ...form.tgInline };
      } else {
        const idNum = Number(form.tgChoice);
        if (!Number.isFinite(idNum) || idNum <= 0) {
          setFormError('pick a target group');
          setSubmitting(false);
          return;
        }
        base.target_group_id = idNum;
      }

      if (form.id) {
        const existing = hosts?.find((h) => h.id === form.id);
        await api.updateHost(form.id, {
          ...base,
          enabled: existing?.enabled ?? true,
        } as HostInput & { enabled: boolean });
        toasts.push(`updated ${form.domain}`, 'success');
      } else {
        await api.createHost(base);
        toasts.push(`created ${form.domain}`, 'success');
      }
      setModalOpen(false);
      await refresh();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : 'save failed');
    } finally {
      setSubmitting(false);
    }
  }

  async function onToggle(h: Host) {
    try {
      await api.toggleHost(h.id);
      toasts.push(`${h.domain} ${h.enabled ? 'disabled' : 'enabled'}`, 'success');
      await refresh();
    } catch (err) {
      toasts.push(err instanceof ApiError ? err.message : 'toggle failed', 'error');
    }
  }

  // onToggleAuth flips auth_required via PATCH-style PUT. The panel's
  // API expects the full mutable set on PUT /hosts/{id}, so we
  // pass-through the current host fields and only change auth_required.
  async function onToggleAuth(h: Host) {
    try {
      await api.updateHost(h.id, {
        domain: h.domain,
        target_group_id: h.target_group_id,
        tls_mode: h.tls_mode,
        tls_email: h.tls_email,
        tls_acme_ca_url: h.tls_acme_ca_url,
        tls_challenge: h.tls_challenge,
        tls_dns_provider: h.tls_dns_provider || 'cloudflare',
        enabled: h.enabled,
        auth_required: !h.auth_required,
      } as HostInput & { enabled: boolean });
      toasts.push(
        `${h.domain} auth ${!h.auth_required ? 'required' : 'public'}`,
        'success',
      );
      await refresh();
    } catch (err) {
      toasts.push(
        err instanceof ApiError ? err.message : 'auth toggle failed',
        'error',
      );
    }
  }

  async function onDelete(h: Host) {
    if (!window.confirm(`Delete host ${h.domain}? Caddy is reconciled on save.`)) return;
    try {
      await api.deleteHost(h.id);
      toasts.push(`deleted ${h.domain}`, 'success');
      await refresh();
    } catch (err) {
      toasts.push(err instanceof ApiError ? err.message : 'delete failed', 'error');
    }
  }

  const tgMap = useMemo(() => {
    const m = new Map<number, TargetGroup>();
    for (const t of tgs) m.set(t.id, t);
    return m;
  }, [tgs]);

  return (
    <div className="p-6 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-semibold">Hosts</h1>
        <button
          type="button"
          onClick={openCreate}
          className="flex items-center gap-2 px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 text-sm font-medium"
        >
          <Plus className="w-4 h-4" />
          Add host
        </button>
      </div>

      {loadError && (
        <div className="mb-4 px-3 py-2 rounded bg-red-950/40 border border-red-900 text-sm text-red-300">
          {loadError}
        </div>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs tracking-wide">
            <tr>
              <th className="text-left px-4 py-2">Domain</th>
              <th className="text-left px-4 py-2">Upstream</th>
              <th className="text-left px-4 py-2">TLS</th>
              <th className="text-left px-4 py-2">Rules</th>
              <th className="text-left px-4 py-2">Enabled</th>
              <th className="text-left px-4 py-2">Auth</th>
              <th className="text-right px-4 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {hosts === null && (
              <tr>
                <td colSpan={7} className="px-4 py-4 text-slate-500">
                  loading...
                </td>
              </tr>
            )}
            {hosts !== null && hosts.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-4 text-slate-500">
                  no hosts yet. Click Add host to create one.
                </td>
              </tr>
            )}
            {hosts?.map((h) => {
              const tg = h.target_group ?? tgMap.get(h.target_group_id);
              const https = tg?.protocol === 'https';
              const tgFull = tgMap.get(h.target_group_id);
              const notVerified = https && tgFull && !tgFull.verify_tls;
              return (
                <tr key={h.id} className="border-t border-slate-800">
                  <td className="px-4 py-2 font-mono">{h.domain}</td>
                  <td className="px-4 py-2">
                    {tg ? (
                      <div className="flex items-center gap-2 flex-wrap">
                        <Link
                          to={`/target-groups/${h.target_group_id}`}
                          className="font-mono text-sky-400 hover:underline"
                        >
                          {tg.name}
                        </Link>
                        <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                          {tg.protocol}
                        </span>
                        <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                          {tg.algorithm}
                        </span>
                        <span className="text-xs text-slate-400">
                          {tg.targets_enabled_count}/{tg.targets_count} targets
                        </span>
                        {notVerified && (
                          <span className="inline-flex items-center gap-1 text-[11px] px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800">
                            <ShieldAlert className="w-3 h-3" />
                            TLS not verified
                          </span>
                        )}
                      </div>
                    ) : (
                      <span className="text-slate-500">tg {h.target_group_id}</span>
                    )}
                  </td>
                  <td className="px-4 py-2">
                    <span
                      className={`text-xs px-2 py-0.5 rounded ${
                        h.tls_mode === 'auto'
                          ? 'bg-sky-900 text-sky-200'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {h.tls_mode}
                    </span>
                  </td>
                  <td className="px-4 py-2">
                    <Link
                      to={`/hosts/${h.id}/rules`}
                      className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded border border-slate-700 hover:bg-slate-800 text-slate-300"
                      title="edit rules"
                    >
                      <ListOrdered className="w-3 h-3" />
                      {h.rules_count > 0 ? `${h.rules_count} rules` : 'add'}
                    </Link>
                  </td>
                  <td className="px-4 py-2">
                    <span
                      className={`text-xs px-2 py-0.5 rounded ${
                        h.enabled
                          ? 'bg-emerald-900 text-emerald-200'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {h.enabled ? 'on' : 'off'}
                    </span>
                  </td>
                  <td className="px-4 py-2">
                    <button
                      type="button"
                      onClick={() => onToggleAuth(h)}
                      title={
                        h.auth_required
                          ? 'Require authentication — click to make public'
                          : 'Public — click to require authentication'
                      }
                      className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded border ${
                        h.auth_required
                          ? 'bg-sky-900 text-sky-200 border-sky-800'
                          : 'bg-slate-800 text-slate-400 border-slate-700'
                      }`}
                    >
                      {h.auth_required ? (
                        <Lock className="w-3 h-3" />
                      ) : (
                        <Unlock className="w-3 h-3" />
                      )}
                      {h.auth_required ? 'required' : 'public'}
                    </button>
                  </td>
                  <td className="px-4 py-2 text-right">
                    <div className="inline-flex items-center gap-1">
                      <Link
                        to={`/hosts/${h.id}/security`}
                        aria-label="security"
                        title="security"
                        className="p-1.5 rounded border border-slate-700 hover:bg-slate-800 text-slate-300"
                      >
                        <Shield className="w-4 h-4" />
                      </Link>
                      <Link
                        to={`/logs?host_id=${h.id}`}
                        aria-label="view logs"
                        title="view logs"
                        className="p-1.5 rounded border border-slate-700 hover:bg-slate-800 text-slate-300"
                      >
                        <FileText className="w-4 h-4" />
                      </Link>
                      <IconButton label="toggle" onClick={() => onToggle(h)}>
                        <Power className="w-4 h-4" />
                      </IconButton>
                      <IconButton label="edit" onClick={() => openEdit(h)}>
                        <Pencil className="w-4 h-4" />
                      </IconButton>
                      <IconButton label="delete" onClick={() => onDelete(h)} danger>
                        <Trash2 className="w-4 h-4" />
                      </IconButton>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <Modal
        open={modalOpen}
        title={form.id ? `Edit ${form.domain}` : 'Add host'}
        onClose={() => setModalOpen(false)}
      >
        <form onSubmit={onSubmit} className="space-y-3 text-sm">
          <div>
            <label className="block text-slate-300 mb-1">Domain</label>
            <input
              type="text"
              required
              value={form.domain}
              onChange={(e) => setForm({ ...form, domain: e.target.value })}
              placeholder="foo.example.com"
              className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500 font-mono"
            />
          </div>

          <div>
            <label className="block text-slate-300 mb-1">Target group</label>
            <select
              value={form.tgChoice}
              onChange={(e) => setForm({ ...form, tgChoice: e.target.value })}
              className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500"
            >
              {tgs.map((tg) => (
                <option key={tg.id} value={tg.id}>
                  {tg.name} — {tg.protocol} / {tg.algorithm} ({tg.targets_enabled_count}/
                  {tg.targets_count} targets)
                </option>
              ))}
              {!form.id && <option value={INLINE_CHOICE}>+ Create new target group</option>}
            </select>
          </div>

          {form.tgChoice === INLINE_CHOICE && (
            <div className="p-3 rounded border border-slate-800 bg-slate-950/60">
              <div className="text-xs uppercase text-slate-500 tracking-wide mb-2">
                New target group
              </div>
              <TargetGroupForm
                value={form.tgInline}
                onChange={(v) => setForm({ ...form, tgInline: v })}
                requireTargets
              />
            </div>
          )}

          <div>
            <label className="block text-slate-300 mb-1">TLS mode</label>
            <select
              value={form.tls_mode}
              onChange={(e) => setForm({ ...form, tls_mode: e.target.value as TLSMode })}
              className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500"
            >
              <option value="auto">auto (Let's Encrypt)</option>
              <option value="none">none (plain HTTP)</option>
              <option value="manual">manual (upload your own cert)</option>
            </select>
          </div>

          {form.tls_mode === 'manual' && form.id !== undefined && (
            <ManualCertSection hostID={form.id} domain={form.domain} />
          )}
          {form.tls_mode === 'manual' && form.id === undefined && (
            <div className="px-3 py-2 rounded bg-amber-950/40 border border-amber-900 text-xs text-amber-200">
              Save the host first, then import a certificate from{' '}
              <strong>Certificates → Imported → Import certificate</strong>. Caddy returns 503
              for this host until a cert is uploaded.
            </div>
          )}

          {form.tls_mode === 'auto' && (
            <div className="space-y-2">
              <label className="block text-slate-300">TLS challenge</label>
              <ChallengeRadio
                value={form.tls_challenge}
                label="DNS-01"
                hint="Works behind CGNAT; supports wildcards. Provider credentials live in Settings → DNS providers."
                challenge="dns"
                onChange={(c) => setForm({ ...form, tls_challenge: c })}
              />
              <ChallengeRadio
                value={form.tls_challenge}
                label="HTTP-01"
                hint="Port 80 reachable from the internet. No DNS API token needed. Cannot issue wildcards."
                challenge="http"
                onChange={(c) => setForm({ ...form, tls_challenge: c })}
              />
              <ChallengeRadio
                value={form.tls_challenge}
                label="TLS-ALPN-01"
                hint="Port 443 reachable from the internet. Useful when port 80 is blocked. Cannot issue wildcards."
                challenge="tls-alpn"
                onChange={(c) => setForm({ ...form, tls_challenge: c })}
              />
              {form.tls_challenge === 'dns' && (
                <DNSProviderPicker
                  value={form.tls_dns_provider}
                  onChange={(v) => setForm({ ...form, tls_dns_provider: v })}
                  providers={enabledProviders}
                />
              )}
              {(form.tls_challenge === 'http' || form.tls_challenge === 'tls-alpn') && (
                <div className="flex items-start gap-2 bg-amber-950/40 border border-amber-900 rounded px-3 py-2 text-xs text-amber-200">
                  <span>
                    Requires <strong>{form.tls_challenge === 'http' ? 'port 80' : 'port 443'}</strong>{' '}
                    reachable from the Let's Encrypt validation servers. Won't work behind CGNAT
                    or an ISP that blocks the port. Cannot issue wildcard certificates.
                  </span>
                </div>
              )}
            </div>
          )}

          <div>
            <label className="block text-slate-300 mb-1">TLS email</label>
            <input
              type="text"
              value={form.tls_email}
              onChange={(e) => setForm({ ...form, tls_email: e.target.value })}
              placeholder="ops@example.com"
              required={form.tls_mode === 'auto'}
              className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500 font-mono"
            />
          </div>

          {form.tls_mode === 'auto' && (
            <details className="border border-slate-800 rounded px-3 py-2 text-sm">
              <summary className="cursor-pointer text-slate-400 text-xs uppercase tracking-wide">
                Advanced
              </summary>
              <div className="mt-3">
                <label className="block text-slate-300 mb-1">ACME CA URL override</label>
                <input
                  type="url"
                  value={form.tls_acme_ca_url}
                  onChange={(e) => setForm({ ...form, tls_acme_ca_url: e.target.value })}
                  placeholder="(inherit from Settings -> ACME CA)"
                  className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500 font-mono text-xs"
                />
                <p className="mt-1 text-xs text-slate-500">
                  Optional. Overrides the global <code className="font-mono">acme.ca_url</code>{' '}
                  setting for this host only. Typical use: debug one host on Let's Encrypt
                  staging without flipping the rest of the panel. Leave empty to inherit.
                </p>
              </div>
            </details>
          )}

          {formError && (
            <div className="px-3 py-2 rounded bg-red-950/40 border border-red-900 text-red-300">
              {formError}
            </div>
          )}
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setModalOpen(false)}
              className="px-3 py-1.5 rounded border border-slate-700 hover:bg-slate-800"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 font-medium"
            >
              {submitting ? 'saving...' : form.id ? 'Save' : 'Create'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}

function IconButton({
  children,
  onClick,
  label,
  danger,
}: {
  children: React.ReactNode;
  onClick: () => void;
  label: string;
  danger?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={label}
      title={label}
      className={`p-1.5 rounded border border-slate-700 hover:bg-slate-800 ${
        danger ? 'text-red-400 hover:text-red-300' : 'text-slate-300'
      }`}
    >
      {children}
    </button>
  );
}

// DNSProviderPicker renders the "which provider" selector shown
// when tls_challenge=dns. Three states:
//   * 0 providers enabled+configured: amber warning + deep link to
//     Settings, Save is blocked client-side (onSubmit guards too).
//   * 1 provider: auto-select + read-only label ("Using <name>").
//     The form state already carries the value; we just render.
//   * >=2 providers: native <select>.
// When the host's current value is not in the enabled list (e.g. the
// provider was disabled AFTER the host was created), we still render
// it but mark it "(disabled)" so the operator sees the drift.
function DNSProviderPicker({
  value,
  onChange,
  providers,
}: {
  value: string;
  onChange: (v: string) => void;
  providers: DNSProvider[];
}) {
  // Keep the current value selectable even when the matching row is
  // not enabled + configured, so editing an existing host does not
  // silently rewrite its provider choice.
  const currentMissing =
    value !== '' && !providers.some((p) => p.name === value);

  if (providers.length === 0 && !currentMissing) {
    return (
      <div className="flex items-start gap-2 bg-amber-950/40 border border-amber-900 rounded px-3 py-2 text-xs text-amber-200">
        <span>
          No DNS providers are configured yet.{' '}
          <Link to="/settings" className="underline hover:text-amber-100">
            Go to Settings → DNS providers
          </Link>{' '}
          to enable one (Cloudflare, Route 53, ...) before selecting
          DNS-01 here.
        </span>
      </div>
    );
  }

  if (providers.length === 1 && !currentMissing) {
    const only = providers[0]!;
    return (
      <DNSProviderSingleton
        provider={only}
        value={value}
        onChange={onChange}
      />
    );
  }

  return (
    <div className="pl-6">
      <label className="block text-slate-400 text-xs mb-1">DNS provider</label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500"
      >
        {providers.map((p) => (
          <option key={p.name} value={p.name}>
            {p.display_name}
          </option>
        ))}
        {currentMissing && (
          <option value={value}>
            {value} (not enabled)
          </option>
        )}
      </select>
      {currentMissing && (
        <p className="mt-1 text-xs text-amber-300">
          The provider saved on this host is not enabled in Settings.
          Pick one from the list above, or re-enable{' '}
          <span className="font-mono">{value}</span> in Settings before
          saving.
        </p>
      )}
    </div>
  );
}

// DNSProviderSingleton is the "only one provider enabled" branch.
// Kept as its own component so the sync-to-parent effect runs inside
// a hook, not during render (React would warn, and strict mode would
// re-render twice).
function DNSProviderSingleton({
  provider,
  value,
  onChange,
}: {
  provider: DNSProvider;
  value: string;
  onChange: (v: string) => void;
}) {
  useEffect(() => {
    if (value !== provider.name) onChange(provider.name);
  }, [value, provider.name, onChange]);
  return (
    <div className="text-xs text-slate-400 pl-6">
      Using <span className="font-mono text-slate-200">{provider.display_name}</span>{' '}
      from <Link to="/settings" className="underline hover:text-slate-200">Settings</Link>.
    </div>
  );
}

function ChallengeRadio({
  value,
  challenge,
  label,
  hint,
  onChange,
}: {
  value: TLSChallenge;
  challenge: TLSChallenge;
  label: string;
  hint: string;
  onChange: (c: TLSChallenge) => void;
}) {
  return (
    <label className="flex items-start gap-2 cursor-pointer">
      <input
        type="radio"
        name="tls-challenge"
        checked={value === challenge}
        onChange={() => onChange(challenge)}
        className="mt-1 accent-sky-600"
      />
      <span>
        <span className="text-slate-200">{label}</span>
        <span className="block text-xs text-slate-500">{hint}</span>
      </span>
    </label>
  );
}
