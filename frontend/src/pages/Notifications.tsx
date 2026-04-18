import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  Bell,
  CheckCircle,
  ChevronRight,
  Monitor,
  Pencil,
  Plus,
  Power,
  RefreshCw,
  Send,
  Trash2,
  XCircle,
} from 'lucide-react';
import {
  ApiError,
  Host,
  NOTIF_UNCHANGED,
  NotifChannel,
  NotifChannelInput,
  NotifChannelType,
  NotifDelivery,
  NotifEventCatalog,
  NotifRule,
  NotifRuleInput,
  NotifSeverity,
  PushSubscription,
  api,
} from '../api/client';
import Modal from '../components/Modal';
import { useToasts } from '../components/toastsContext';
import { pushSupport, subscribeToPush, unsubscribeFromPush } from '../lib/push';

type Tab = 'channels' | 'rules' | 'history' | 'devices';

export default function Notifications() {
  const [tab, setTab] = useState<Tab>('channels');

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <h1 className="text-2xl font-semibold mb-4 flex items-center gap-2">
        <Bell className="w-6 h-6 text-sky-400" />
        Notifications
      </h1>
      <div className="flex gap-1 border-b border-slate-800 mb-4">
        {(
          [
            ['channels', 'Channels'],
            ['rules', 'Rules'],
            ['history', 'History'],
            ['devices', 'My Devices'],
          ] as [Tab, string][]
        ).map(([t, label]) => (
          <button
            key={t}
            type="button"
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm border-b-2 -mb-px ${
              tab === t
                ? 'border-sky-500 text-sky-300'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === 'channels' && <ChannelsTab />}
      {tab === 'rules' && <RulesTab />}
      {tab === 'history' && <HistoryTab />}
      {tab === 'devices' && <DevicesTab />}
    </div>
  );
}

// ---------- Channels tab ----------

function ChannelsTab() {
  const toasts = useToasts();
  const [rows, setRows] = useState<NotifChannel[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<NotifChannel | null>(null);

  const refresh = useCallback(async () => {
    try {
      const r = await api.listNotifChannels();
      setRows(r);
      setErr(null);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'load failed');
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function onToggle(ch: NotifChannel) {
    try {
      await api.toggleNotifChannel(ch.id);
      await refresh();
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'toggle failed', 'error');
    }
  }
  async function onDelete(ch: NotifChannel) {
    if (!window.confirm(`Delete channel "${ch.name}"?`)) return;
    try {
      await api.deleteNotifChannel(ch.id);
      toasts.push(`deleted ${ch.name}`, 'success');
      await refresh();
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'delete failed', 'error');
    }
  }
  async function onTest(ch: NotifChannel) {
    try {
      const r = await api.testNotifChannel(ch.id);
      if (r.success) {
        toasts.push(`test sent via ${ch.name}`, 'success');
      } else {
        toasts.push(r.error_message ?? 'test failed', 'error');
      }
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'test failed', 'error');
    }
  }

  return (
    <>
      {err && <ErrorBar msg={err} />}
      <div className="flex items-center justify-between mb-3">
        <p className="text-sm text-slate-400">
          Channels are dispatch endpoints. Secrets are encrypted at rest with AES-GCM.
        </p>
        <button
          type="button"
          onClick={() => {
            setEditing(null);
            setModalOpen(true);
          }}
          className="flex items-center gap-2 px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 text-sm font-medium"
        >
          <Plus className="w-4 h-4" /> Add channel
        </button>
      </div>
      {rows === null ? (
        <Loading />
      ) : rows.length === 0 ? (
        <Empty msg="No channels yet" />
      ) : (
        <table className="w-full text-sm">
          <thead className="text-slate-400 uppercase text-xs tracking-wide">
            <tr>
              <th className="text-left px-2 py-1">Name</th>
              <th className="text-left px-2 py-1">Type</th>
              <th className="text-left px-2 py-1">Enabled</th>
              <th className="text-left px-2 py-1">Rate limit</th>
              <th className="text-right px-2 py-1">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((ch) => (
              <tr key={ch.id} className="border-t border-slate-800">
                <td className="px-2 py-2 font-medium">{ch.name}</td>
                <td className="px-2 py-2">
                  <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                    {ch.type}
                  </span>
                </td>
                <td className="px-2 py-2">
                  <span
                    className={`text-xs px-2 py-0.5 rounded ${
                      ch.enabled
                        ? 'bg-emerald-900 text-emerald-200'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {ch.enabled ? 'on' : 'off'}
                  </span>
                </td>
                <td className="px-2 py-2 text-slate-400 text-xs">
                  {ch.rate_limit_per_minute}/min
                </td>
                <td className="px-2 py-2 text-right">
                  <IconBtn label="test" onClick={() => onTest(ch)}>
                    <Send className="w-3.5 h-3.5" />
                  </IconBtn>
                  <IconBtn label="toggle" onClick={() => onToggle(ch)}>
                    <Power className="w-3.5 h-3.5" />
                  </IconBtn>
                  <IconBtn
                    label="edit"
                    onClick={() => {
                      setEditing(ch);
                      setModalOpen(true);
                    }}
                  >
                    <Pencil className="w-3.5 h-3.5" />
                  </IconBtn>
                  <IconBtn label="delete" danger onClick={() => onDelete(ch)}>
                    <Trash2 className="w-3.5 h-3.5" />
                  </IconBtn>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <ChannelFormModal
        open={modalOpen}
        editing={editing}
        onClose={() => setModalOpen(false)}
        onSaved={async () => {
          setModalOpen(false);
          await refresh();
        }}
      />
    </>
  );
}

function ChannelFormModal({
  open,
  editing,
  onClose,
  onSaved,
}: {
  open: boolean;
  editing: NotifChannel | null;
  onClose: () => void;
  onSaved: () => Promise<void> | void;
}) {
  const toasts = useToasts();
  const [name, setName] = useState('');
  const [type, setType] = useState<NotifChannelType>('webhook');
  const [enabled, setEnabled] = useState(true);
  const [rateLimit, setRateLimit] = useState(10);
  const [template, setTemplate] = useState('');
  const [cfg, setCfg] = useState<Record<string, unknown>>({});
  const [err, setErr] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    if (editing) {
      setName(editing.name);
      setType(editing.type);
      setEnabled(editing.enabled);
      setRateLimit(editing.rate_limit_per_minute);
      setTemplate(editing.template);
      setCfg({ ...editing.config });
    } else {
      setName('');
      setType('webhook');
      setEnabled(true);
      setRateLimit(10);
      setTemplate('');
      setCfg({});
    }
    setErr(null);
  }, [open, editing]);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setSubmitting(true);
    setErr(null);
    const input: NotifChannelInput = {
      name,
      type,
      enabled,
      config: cfg,
      template,
      rate_limit_per_minute: rateLimit,
    };
    try {
      if (editing) {
        await api.updateNotifChannel(editing.id, input);
        toasts.push('channel updated', 'success');
      } else {
        await api.createNotifChannel(input);
        toasts.push('channel created', 'success');
      }
      await onSaved();
    } catch (ex) {
      setErr(ex instanceof ApiError ? ex.message : 'save failed');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Modal open={open} title={editing ? 'Edit channel' : 'Add channel'} onClose={onClose}>
      <form onSubmit={onSubmit} className="space-y-3 text-sm">
        <div>
          <label className="block text-slate-300 mb-1">Name</label>
          <input
            type="text"
            required
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700"
          />
        </div>
        <div>
          <label className="block text-slate-300 mb-1">Type</label>
          <select
            value={type}
            onChange={(e) => {
              const t = e.target.value as NotifChannelType;
              setType(t);
              if (!editing) setCfg({});
            }}
            disabled={!!editing}
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 disabled:opacity-60"
          >
            <option value="webhook">Webhook</option>
            <option value="email">Email (SMTP)</option>
            <option value="telegram">Telegram</option>
            <option value="browser_push">Browser Push</option>
          </select>
          {editing && (
            <p className="text-xs text-slate-500 mt-1">
              Channel type is immutable after creation.
            </p>
          )}
        </div>

        {type === 'webhook' && <WebhookFields cfg={cfg} setCfg={setCfg} editing={!!editing} />}
        {type === 'email' && <EmailFields cfg={cfg} setCfg={setCfg} editing={!!editing} />}
        {type === 'telegram' && <TelegramFields cfg={cfg} setCfg={setCfg} editing={!!editing} />}
        {type === 'browser_push' && <BrowserPushFields />}

        <div>
          <label className="block text-slate-300 mb-1">Rate limit (per minute)</label>
          <input
            type="number"
            min={0}
            max={10000}
            value={rateLimit}
            onChange={(e) => setRateLimit(Number(e.target.value))}
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
          />
        </div>
        <div>
          <label className="block text-slate-300 mb-1">
            Template (Go text/template; blank = default per type)
          </label>
          <textarea
            value={template}
            onChange={(e) => setTemplate(e.target.value)}
            rows={4}
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono text-xs"
            placeholder="e.g. {{ .Severity | upper }}: {{ .Message }} ({{ .HostDomain }})"
          />
          <p className="text-xs text-slate-500 mt-1">
            Variables: .Type .Severity .HostDomain .HostID .Timestamp .Message .Data
            · Funcs: upper, lower, title, iso8601, date, severityEmoji, truncate, json, jsonIndent, jsonEscape, escapeMD
          </p>
        </div>
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
            className="w-4 h-4 accent-sky-600"
          />
          <span>Enabled</span>
        </label>
        {err && (
          <div className="px-3 py-2 rounded bg-red-950/40 border border-red-900 text-red-300">
            {err}
          </div>
        )}
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 rounded border border-slate-700 hover:bg-slate-800"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={submitting}
            className="px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 font-medium"
          >
            {submitting ? 'saving...' : editing ? 'Save' : 'Create'}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function WebhookFields({
  cfg,
  setCfg,
  editing,
}: {
  cfg: Record<string, unknown>;
  setCfg: (c: Record<string, unknown>) => void;
  editing: boolean;
}) {
  const url = (cfg.url as string) ?? '';
  const method = (cfg.method as string) ?? 'POST';
  const contentType = (cfg.content_type as string) ?? 'application/json';
  // headers can be: object (set fresh), "__UNCHANGED__" (kept), or missing
  const headersSet = cfg.headers === NOTIF_UNCHANGED || (typeof cfg.headers === 'object' && cfg.headers !== null);
  const [editHeaders, setEditHeaders] = useState(!editing);

  return (
    <>
      <div>
        <label className="block text-slate-300 mb-1">URL</label>
        <input
          type="url"
          required
          value={url}
          onChange={(e) => setCfg({ ...cfg, url: e.target.value })}
          placeholder="https://httpbin.org/anything"
          className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
        />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-slate-300 mb-1">Method</label>
          <select
            value={method}
            onChange={(e) => setCfg({ ...cfg, method: e.target.value })}
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700"
          >
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
          </select>
        </div>
        <div>
          <label className="block text-slate-300 mb-1">Content-Type</label>
          <input
            type="text"
            value={contentType}
            onChange={(e) => setCfg({ ...cfg, content_type: e.target.value })}
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
          />
        </div>
      </div>
      <div>
        <label className="block text-slate-300 mb-1">
          Custom headers (encrypted; treated as secret blob)
        </label>
        {editing && headersSet && !editHeaders ? (
          <div className="flex items-center gap-2">
            <code className="px-2 py-1 rounded bg-slate-800 text-slate-400 text-xs">
              ●●●●●●●● (set)
            </code>
            <button
              type="button"
              onClick={() => {
                setCfg({ ...cfg, headers: {} });
                setEditHeaders(true);
              }}
              className="text-xs px-2 py-1 rounded border border-slate-700 hover:bg-slate-800"
            >
              Replace
            </button>
          </div>
        ) : (
          <HeadersEditor
            value={(cfg.headers as Record<string, string>) ?? {}}
            onChange={(h) => setCfg({ ...cfg, headers: h })}
          />
        )}
        <p className="text-xs text-slate-500 mt-1">
          Tip: Put <code>Authorization: Bearer …</code> here. The whole map is encrypted.
        </p>
      </div>
    </>
  );
}

function HeadersEditor({
  value,
  onChange,
}: {
  value: Record<string, string>;
  onChange: (v: Record<string, string>) => void;
}) {
  const entries = Object.entries(value);
  function setKey(idx: number, k: string) {
    const next: Record<string, string> = {};
    entries.forEach(([kk, vv], i) => {
      next[i === idx ? k : kk] = vv;
    });
    onChange(next);
  }
  function setVal(idx: number, v: string) {
    const next = { ...value };
    const key = entries[idx]?.[0];
    if (key !== undefined) next[key] = v;
    onChange(next);
  }
  function add() {
    onChange({ ...value, '': '' });
  }
  function del(k: string) {
    const next = { ...value };
    delete next[k];
    onChange(next);
  }
  return (
    <div className="space-y-1">
      {entries.length === 0 && (
        <p className="text-xs text-slate-500">No custom headers.</p>
      )}
      {entries.map(([k, v], i) => (
        <div key={i} className="flex gap-2">
          <input
            type="text"
            value={k}
            onChange={(e) => setKey(i, e.target.value)}
            placeholder="Header"
            className="flex-1 px-2 py-1 rounded bg-slate-800 border border-slate-700 font-mono text-xs"
          />
          <input
            type="text"
            value={v}
            onChange={(e) => setVal(i, e.target.value)}
            placeholder="Value"
            className="flex-1 px-2 py-1 rounded bg-slate-800 border border-slate-700 font-mono text-xs"
          />
          <button
            type="button"
            onClick={() => del(k)}
            className="px-2 text-slate-500 hover:text-red-400"
          >
            <Trash2 className="w-3 h-3" />
          </button>
        </div>
      ))}
      <button
        type="button"
        onClick={add}
        className="text-xs px-2 py-1 rounded border border-slate-700 hover:bg-slate-800"
      >
        + Add header
      </button>
    </div>
  );
}

function EmailFields({
  cfg,
  setCfg,
  editing,
}: {
  cfg: Record<string, unknown>;
  setCfg: (c: Record<string, unknown>) => void;
  editing: boolean;
}) {
  const passSet = cfg.smtp_password === NOTIF_UNCHANGED;
  const [editPass, setEditPass] = useState(!editing || !passSet);
  return (
    <div className="grid grid-cols-2 gap-3">
      <div>
        <label className="block text-slate-300 mb-1">SMTP host</label>
        <input
          type="text"
          required
          value={(cfg.smtp_host as string) ?? ''}
          onChange={(e) => setCfg({ ...cfg, smtp_host: e.target.value })}
          className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
        />
      </div>
      <div>
        <label className="block text-slate-300 mb-1">Port</label>
        <input
          type="number"
          min={1}
          max={65535}
          value={(cfg.smtp_port as number) ?? 587}
          onChange={(e) => setCfg({ ...cfg, smtp_port: Number(e.target.value) })}
          className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
        />
      </div>
      <div>
        <label className="block text-slate-300 mb-1">Username</label>
        <input
          type="text"
          value={(cfg.smtp_username as string) ?? ''}
          onChange={(e) => setCfg({ ...cfg, smtp_username: e.target.value })}
          className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
        />
      </div>
      <div>
        <label className="block text-slate-300 mb-1">Password</label>
        {editing && passSet && !editPass ? (
          <div className="flex items-center gap-2 h-[38px]">
            <code className="px-2 py-1 rounded bg-slate-800 text-slate-400 text-xs">●●●●●●●●</code>
            <button
              type="button"
              onClick={() => {
                setCfg({ ...cfg, smtp_password: '' });
                setEditPass(true);
              }}
              className="text-xs px-2 py-1 rounded border border-slate-700 hover:bg-slate-800"
            >
              Change
            </button>
          </div>
        ) : (
          <input
            type="password"
            value={(cfg.smtp_password as string) ?? ''}
            onChange={(e) => setCfg({ ...cfg, smtp_password: e.target.value })}
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
          />
        )}
      </div>
      <div className="col-span-2">
        <label className="block text-slate-300 mb-1">Auth (PLAIN / LOGIN)</label>
        <select
          value={(cfg.smtp_auth as string) ?? 'PLAIN'}
          onChange={(e) => setCfg({ ...cfg, smtp_auth: e.target.value })}
          className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700"
        >
          <option value="PLAIN">PLAIN</option>
          <option value="LOGIN">LOGIN</option>
        </select>
      </div>
      <label className="flex items-center gap-2 col-span-1">
        <input
          type="checkbox"
          checked={(cfg.use_starttls as boolean) ?? false}
          onChange={(e) => setCfg({ ...cfg, use_starttls: e.target.checked })}
          className="w-4 h-4 accent-sky-600"
        />
        <span>STARTTLS (port 587)</span>
      </label>
      <label className="flex items-center gap-2 col-span-1">
        <input
          type="checkbox"
          checked={(cfg.use_tls as boolean) ?? false}
          onChange={(e) => setCfg({ ...cfg, use_tls: e.target.checked })}
          className="w-4 h-4 accent-sky-600"
        />
        <span>Implicit TLS (port 465)</span>
      </label>
      <div className="col-span-2">
        <label className="block text-slate-300 mb-1">From</label>
        <input
          type="email"
          required
          value={(cfg.from as string) ?? ''}
          onChange={(e) => setCfg({ ...cfg, from: e.target.value })}
          placeholder="argos@example.com"
          className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
        />
      </div>
      <div className="col-span-2">
        <label className="block text-slate-300 mb-1">To (comma-separated)</label>
        <input
          type="text"
          required
          value={(cfg.to as string) ?? ''}
          onChange={(e) => setCfg({ ...cfg, to: e.target.value })}
          className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
        />
      </div>
      <div className="col-span-2">
        <label className="block text-slate-300 mb-1">Subject</label>
        <input
          type="text"
          value={(cfg.subject as string) ?? ''}
          onChange={(e) => setCfg({ ...cfg, subject: e.target.value })}
          placeholder="[argos] {{ .Severity }}: {{ .Type }}"
          className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
        />
      </div>
    </div>
  );
}

function TelegramFields({
  cfg,
  setCfg,
  editing,
}: {
  cfg: Record<string, unknown>;
  setCfg: (c: Record<string, unknown>) => void;
  editing: boolean;
}) {
  const tokenSet = cfg.bot_token === NOTIF_UNCHANGED;
  const [editTok, setEditTok] = useState(!editing || !tokenSet);
  return (
    <div className="space-y-3">
      <div>
        <label className="block text-slate-300 mb-1">Bot token</label>
        {editing && tokenSet && !editTok ? (
          <div className="flex items-center gap-2">
            <code className="px-2 py-1 rounded bg-slate-800 text-slate-400 text-xs">●●●●●●●●</code>
            <button
              type="button"
              onClick={() => {
                setCfg({ ...cfg, bot_token: '' });
                setEditTok(true);
              }}
              className="text-xs px-2 py-1 rounded border border-slate-700 hover:bg-slate-800"
            >
              Change
            </button>
          </div>
        ) : (
          <input
            type="password"
            value={(cfg.bot_token as string) ?? ''}
            onChange={(e) => setCfg({ ...cfg, bot_token: e.target.value })}
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
            placeholder="123456:ABC-DEF..."
          />
        )}
        <p className="text-xs text-slate-500 mt-1">
          Crea un bot con @BotFather y pega el token aquí.
        </p>
      </div>
      <div>
        <label className="block text-slate-300 mb-1">Chat ID</label>
        <input
          type="text"
          required
          value={(cfg.chat_id as string) ?? ''}
          onChange={(e) => setCfg({ ...cfg, chat_id: e.target.value })}
          placeholder="123456789 o @channel"
          className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
        />
        <p className="text-xs text-slate-500 mt-1">
          Manda <code>/start</code> a tu bot y usa <code>@userinfobot</code> para obtener tu ID.
        </p>
      </div>
    </div>
  );
}

function BrowserPushFields() {
  const support = pushSupport();
  return (
    <div className="space-y-2 text-sm">
      <p className="text-slate-400">
        Las suscripciones se gestionan desde la pestaña <b>My Devices</b>. Esta entrada solo
        controla enabled / rate_limit.
      </p>
      {!support.httpsOk && (
        <div className="flex items-start gap-2 px-3 py-2 rounded bg-amber-950/40 border border-amber-900 text-amber-200 text-xs">
          <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <span>
            Browser Push requires HTTPS (or localhost). Will work once the panel is served
            behind Caddy with TLS.
          </span>
        </div>
      )}
    </div>
  );
}

// ---------- Rules tab ----------

function RulesTab() {
  const toasts = useToasts();
  const [rows, setRows] = useState<NotifRule[] | null>(null);
  const [channels, setChannels] = useState<NotifChannel[]>([]);
  const [events, setEvents] = useState<NotifEventCatalog[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<NotifRule | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [r, ch, ev, hs] = await Promise.all([
        api.listNotifRules(),
        api.listNotifChannels(),
        api.notifEventTypes(),
        api.listHosts(),
      ]);
      setRows(r);
      setChannels(ch);
      setEvents(ev);
      setHosts(hs);
      setErr(null);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'load failed');
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function onToggle(ru: NotifRule) {
    try {
      await api.toggleNotifRule(ru.id);
      await refresh();
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'toggle failed', 'error');
    }
  }
  async function onDelete(ru: NotifRule) {
    if (!window.confirm(`Delete rule "${ru.name}"?`)) return;
    try {
      await api.deleteNotifRule(ru.id);
      toasts.push(`deleted rule ${ru.name}`, 'success');
      await refresh();
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'delete failed', 'error');
    }
  }

  const chanName = (id: number) => channels.find((c) => c.id === id)?.name ?? `#${id}`;

  return (
    <>
      {err && <ErrorBar msg={err} />}
      <div className="flex items-center justify-between mb-3">
        <p className="text-sm text-slate-400">
          Rules bind an event type to a channel with optional host + severity filters + throttle.
        </p>
        <button
          type="button"
          onClick={() => {
            setEditing(null);
            setModalOpen(true);
          }}
          className="flex items-center gap-2 px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 text-sm font-medium"
        >
          <Plus className="w-4 h-4" /> Add rule
        </button>
      </div>

      {rows === null ? (
        <Loading />
      ) : rows.length === 0 ? (
        <Empty msg="No rules yet. Events are emitted but not dispatched until a rule binds them to a channel." />
      ) : (
        <table className="w-full text-sm">
          <thead className="text-slate-400 uppercase text-xs tracking-wide">
            <tr>
              <th className="text-left px-2 py-1">Name</th>
              <th className="text-left px-2 py-1">Event</th>
              <th className="text-left px-2 py-1">Channel</th>
              <th className="text-left px-2 py-1">Filters</th>
              <th className="text-left px-2 py-1">Throttle</th>
              <th className="text-left px-2 py-1">Enabled</th>
              <th className="text-right px-2 py-1">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((ru) => (
              <tr key={ru.id} className="border-t border-slate-800">
                <td className="px-2 py-2 font-medium">{ru.name}</td>
                <td className="px-2 py-2">
                  <code className="text-xs">{ru.event_type}</code>
                </td>
                <td className="px-2 py-2">{chanName(ru.channel_id)}</td>
                <td className="px-2 py-2 text-xs text-slate-400">
                  {ru.filter_host_ids?.length
                    ? `${ru.filter_host_ids.length} host(s)`
                    : 'all hosts'}
                  {' · '}
                  {ru.filter_severities?.length
                    ? ru.filter_severities.join(',')
                    : 'all severities'}
                </td>
                <td className="px-2 py-2 text-xs text-slate-400">
                  {ru.throttle_window_seconds > 0 ? `${ru.throttle_window_seconds}s` : 'off'}
                </td>
                <td className="px-2 py-2">
                  <span
                    className={`text-xs px-2 py-0.5 rounded ${
                      ru.enabled
                        ? 'bg-emerald-900 text-emerald-200'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {ru.enabled ? 'on' : 'off'}
                  </span>
                </td>
                <td className="px-2 py-2 text-right">
                  <IconBtn label="toggle" onClick={() => onToggle(ru)}>
                    <Power className="w-3.5 h-3.5" />
                  </IconBtn>
                  <IconBtn
                    label="edit"
                    onClick={() => {
                      setEditing(ru);
                      setModalOpen(true);
                    }}
                  >
                    <Pencil className="w-3.5 h-3.5" />
                  </IconBtn>
                  <IconBtn label="delete" danger onClick={() => onDelete(ru)}>
                    <Trash2 className="w-3.5 h-3.5" />
                  </IconBtn>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <RuleFormModal
        open={modalOpen}
        editing={editing}
        channels={channels}
        events={events}
        hosts={hosts}
        onClose={() => setModalOpen(false)}
        onSaved={async () => {
          setModalOpen(false);
          await refresh();
        }}
      />
    </>
  );
}

function RuleFormModal({
  open,
  editing,
  channels,
  events,
  hosts,
  onClose,
  onSaved,
}: {
  open: boolean;
  editing: NotifRule | null;
  channels: NotifChannel[];
  events: NotifEventCatalog[];
  hosts: Host[];
  onClose: () => void;
  onSaved: () => Promise<void> | void;
}) {
  const toasts = useToasts();
  const [name, setName] = useState('');
  const [channelID, setChannelID] = useState(0);
  const [eventType, setEventType] = useState('');
  const [hostIDs, setHostIDs] = useState<number[]>([]);
  const [severities, setSeverities] = useState<NotifSeverity[]>([]);
  const [enabled, setEnabled] = useState(true);
  const [throttle, setThrottle] = useState(0);
  const [err, setErr] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    if (editing) {
      setName(editing.name);
      setChannelID(editing.channel_id);
      setEventType(editing.event_type);
      setHostIDs(editing.filter_host_ids ?? []);
      setSeverities(editing.filter_severities ?? []);
      setEnabled(editing.enabled);
      setThrottle(editing.throttle_window_seconds);
    } else {
      setName('');
      setChannelID(channels[0]?.id ?? 0);
      setEventType(events[0]?.type ?? '');
      setHostIDs([]);
      setSeverities([]);
      setEnabled(true);
      setThrottle(0);
    }
    setErr(null);
  }, [open, editing, channels, events]);

  const catalogEntry = events.find((e) => e.type === eventType);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setSubmitting(true);
    setErr(null);
    const input: NotifRuleInput = {
      name,
      channel_id: channelID,
      event_type: eventType,
      filter_host_ids: hostIDs,
      filter_severities: severities,
      enabled,
      throttle_window_seconds: throttle,
    };
    try {
      if (editing) {
        await api.updateNotifRule(editing.id, input);
        toasts.push('rule updated', 'success');
      } else {
        await api.createNotifRule(input);
        toasts.push('rule created', 'success');
      }
      await onSaved();
    } catch (ex) {
      setErr(ex instanceof ApiError ? ex.message : 'save failed');
    } finally {
      setSubmitting(false);
    }
  }

  function toggleHost(id: number) {
    setHostIDs((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  }
  function toggleSeverity(s: NotifSeverity) {
    setSeverities((prev) => (prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s]));
  }

  return (
    <Modal open={open} title={editing ? 'Edit rule' : 'Add rule'} onClose={onClose}>
      <form onSubmit={onSubmit} className="space-y-3 text-sm">
        <div>
          <label className="block text-slate-300 mb-1">Name</label>
          <input
            type="text"
            required
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700"
          />
        </div>
        <div>
          <label className="block text-slate-300 mb-1">Channel</label>
          <select
            value={channelID}
            onChange={(e) => setChannelID(Number(e.target.value))}
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700"
          >
            <option value={0}>(select)</option>
            {channels.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name} ({c.type})
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-slate-300 mb-1">Event type</label>
          <select
            value={eventType}
            onChange={(e) => setEventType(e.target.value)}
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
          >
            {events.map((ev) => (
              <option key={ev.type} value={ev.type}>
                {ev.type} [{ev.severity}]
              </option>
            ))}
          </select>
          {catalogEntry && (
            <p className="text-xs text-slate-500 mt-1">
              {catalogEntry.description} — {catalogEntry.trigger_condition}
            </p>
          )}
        </div>
        <div>
          <label className="block text-slate-300 mb-1">Filter hosts (empty = all)</label>
          <div className="max-h-32 overflow-y-auto border border-slate-700 rounded px-2 py-1 space-y-1">
            {hosts.map((h) => (
              <label key={h.id} className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={hostIDs.includes(h.id)}
                  onChange={() => toggleHost(h.id)}
                  className="w-4 h-4 accent-sky-600"
                />
                <span className="font-mono">{h.domain}</span>
              </label>
            ))}
          </div>
        </div>
        <div>
          <label className="block text-slate-300 mb-1">Filter severities (empty = all)</label>
          <div className="flex gap-3">
            {(['info', 'warning', 'error', 'critical'] as NotifSeverity[]).map((s) => (
              <label key={s} className="flex items-center gap-1">
                <input
                  type="checkbox"
                  checked={severities.includes(s)}
                  onChange={() => toggleSeverity(s)}
                  className="w-4 h-4 accent-sky-600"
                />
                <span className="text-xs">{s}</span>
              </label>
            ))}
          </div>
        </div>
        <div>
          <label className="block text-slate-300 mb-1">Throttle window (seconds; 0 = off)</label>
          <input
            type="number"
            min={0}
            max={86400}
            value={throttle}
            onChange={(e) => setThrottle(Number(e.target.value))}
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
          />
        </div>
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
            className="w-4 h-4 accent-sky-600"
          />
          <span>Enabled</span>
        </label>
        {err && (
          <div className="px-3 py-2 rounded bg-red-950/40 border border-red-900 text-red-300">
            {err}
          </div>
        )}
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 rounded border border-slate-700 hover:bg-slate-800"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={submitting}
            className="px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 font-medium"
          >
            {submitting ? 'saving...' : editing ? 'Save' : 'Create'}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// ---------- History tab ----------

function HistoryTab() {
  const toasts = useToasts();
  const [rows, setRows] = useState<NotifDelivery[] | null>(null);
  const [stats, setStats] = useState<Record<string, number>>({});
  const [rangeHours, setRangeHours] = useState(24);
  const [status, setStatus] = useState('');
  const [eventType, setEventType] = useState('');
  const [drawer, setDrawer] = useState<NotifDelivery | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const from = new Date(Date.now() - rangeHours * 3600 * 1000).toISOString();
      const to = new Date().toISOString();
      const params: Record<string, string> = { from, to, stats: '1', limit: '300' };
      if (status) params.status = status;
      if (eventType) params.event_type = eventType;
      const res = await api.listNotifDeliveries(params);
      setRows(res.deliveries);
      setStats(res.stats ?? {});
      setErr(null);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'load failed');
    }
  }, [rangeHours, status, eventType]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function onRetry(d: NotifDelivery) {
    try {
      await api.retryNotifDelivery(d.id);
      toasts.push('retry enqueued', 'success');
      await refresh();
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'retry failed', 'error');
    }
  }

  return (
    <>
      {err && <ErrorBar msg={err} />}
      <div className="flex gap-4 mb-3 text-xs items-end">
        <div>
          <label className="block text-slate-400 mb-0.5">Range</label>
          <select
            value={rangeHours}
            onChange={(e) => setRangeHours(Number(e.target.value))}
            className="px-2 py-1 rounded bg-slate-800 border border-slate-700"
          >
            <option value={24}>last 24h</option>
            <option value={168}>last 7d</option>
            <option value={720}>last 30d</option>
          </select>
        </div>
        <div>
          <label className="block text-slate-400 mb-0.5">Status</label>
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="px-2 py-1 rounded bg-slate-800 border border-slate-700"
          >
            <option value="">any</option>
            <option value="sent">sent</option>
            <option value="failed">failed</option>
            <option value="throttled">throttled</option>
            <option value="rate_limited">rate_limited</option>
            <option value="pending">pending</option>
          </select>
        </div>
        <div>
          <label className="block text-slate-400 mb-0.5">Event type</label>
          <input
            type="text"
            value={eventType}
            onChange={(e) => setEventType(e.target.value)}
            placeholder="any"
            className="px-2 py-1 rounded bg-slate-800 border border-slate-700 font-mono"
          />
        </div>
        <button
          type="button"
          onClick={refresh}
          className="ml-auto flex items-center gap-1 px-2 py-1 rounded border border-slate-700 hover:bg-slate-800"
        >
          <RefreshCw className="w-3 h-3" /> refresh
        </button>
      </div>
      <div className="grid grid-cols-5 gap-2 mb-4 text-xs">
        <StatCard color="emerald" label="sent" value={stats.sent ?? 0} />
        <StatCard color="red" label="failed" value={stats.failed ?? 0} />
        <StatCard color="amber" label="throttled" value={stats.throttled ?? 0} />
        <StatCard color="amber" label="rate limited" value={stats.rate_limited ?? 0} />
        <StatCard color="slate" label="pending" value={stats.pending ?? 0} />
      </div>

      {rows === null ? (
        <Loading />
      ) : rows.length === 0 ? (
        <Empty msg="No deliveries in this range" />
      ) : (
        <table className="w-full text-sm">
          <thead className="text-slate-400 uppercase text-xs tracking-wide">
            <tr>
              <th className="text-left px-2 py-1">Time</th>
              <th className="text-left px-2 py-1">Event</th>
              <th className="text-left px-2 py-1">Status</th>
              <th className="text-left px-2 py-1">Attempts</th>
              <th className="text-left px-2 py-1">Error</th>
              <th className="text-right px-2 py-1">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((d) => (
              <tr
                key={d.id}
                onClick={() => setDrawer(d)}
                className="border-t border-slate-800 cursor-pointer hover:bg-slate-900/60"
              >
                <td className="px-2 py-1.5 text-xs text-slate-400 font-mono">
                  {new Date(d.created_at).toISOString().slice(0, 19).replace('T', ' ')}
                </td>
                <td className="px-2 py-1.5 font-mono text-xs">{d.event_type}</td>
                <td className="px-2 py-1.5">
                  <StatusPill status={d.status} />
                </td>
                <td className="px-2 py-1.5 text-xs text-slate-400">{d.attempts}</td>
                <td className="px-2 py-1.5 text-xs text-slate-500 truncate max-w-[300px]">
                  {d.error_message}
                </td>
                <td className="px-2 py-1.5 text-right">
                  {d.status === 'failed' && (
                    <IconBtn
                      label="retry"
                      onClick={(e) => {
                        e.stopPropagation();
                        onRetry(d);
                      }}
                    >
                      <RefreshCw className="w-3.5 h-3.5" />
                    </IconBtn>
                  )}
                  <ChevronRight className="w-4 h-4 text-slate-600 inline" />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {drawer && (
        <DeliveryDrawer delivery={drawer} onClose={() => setDrawer(null)} onRetry={onRetry} />
      )}
    </>
  );
}

function StatCard({ color, label, value }: { color: string; label: string; value: number }) {
  const bg: Record<string, string> = {
    emerald: 'bg-emerald-950/40 border-emerald-900 text-emerald-300',
    red: 'bg-red-950/40 border-red-900 text-red-300',
    amber: 'bg-amber-950/40 border-amber-900 text-amber-300',
    slate: 'bg-slate-900 border-slate-800 text-slate-300',
  };
  return (
    <div className={`p-3 rounded-lg border ${bg[color] ?? bg.slate}`}>
      <div className="uppercase tracking-wide text-[10px] opacity-80">{label}</div>
      <div className="text-xl font-semibold">{value}</div>
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const cls: Record<string, string> = {
    sent: 'bg-emerald-900 text-emerald-200',
    failed: 'bg-red-900 text-red-200',
    throttled: 'bg-amber-900 text-amber-200',
    rate_limited: 'bg-amber-900 text-amber-200',
    pending: 'bg-slate-800 text-slate-300',
  };
  return (
    <span className={`text-xs px-2 py-0.5 rounded ${cls[status] ?? 'bg-slate-800 text-slate-300'}`}>
      {status}
    </span>
  );
}

function DeliveryDrawer({
  delivery,
  onClose,
  onRetry,
}: {
  delivery: NotifDelivery;
  onClose: () => void;
  onRetry: (d: NotifDelivery) => void;
}) {
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/60" onClick={onClose}>
      <div
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-2xl bg-slate-900 border-l border-slate-700 overflow-y-auto"
      >
        <div className="sticky top-0 flex items-center justify-between px-4 py-3 border-b border-slate-800 bg-slate-900">
          <div>
            <h3 className="text-sm font-semibold">Delivery #{delivery.id}</h3>
            <div className="text-xs text-slate-500 font-mono">{delivery.event_type}</div>
          </div>
          <div className="flex items-center gap-2">
            {delivery.status === 'failed' && (
              <button
                type="button"
                onClick={() => onRetry(delivery)}
                className="flex items-center gap-1 text-xs px-2 py-1 rounded border border-slate-700 hover:bg-slate-800"
              >
                <RefreshCw className="w-3 h-3" /> retry
              </button>
            )}
            <StatusPill status={delivery.status} />
            <button
              type="button"
              onClick={onClose}
              className="text-slate-500 hover:text-slate-200"
            >
              close
            </button>
          </div>
        </div>
        <div className="p-4 space-y-3 text-sm">
          <div>
            <div className="text-xs uppercase text-slate-500 mb-1">Status</div>
            <div>{delivery.status} · {delivery.attempts} attempt(s)</div>
          </div>
          {delivery.error_message && (
            <div>
              <div className="text-xs uppercase text-slate-500 mb-1">Error</div>
              <pre className="text-xs bg-red-950/20 border border-red-900 rounded p-2 whitespace-pre-wrap">{delivery.error_message}</pre>
            </div>
          )}
          <div>
            <div className="text-xs uppercase text-slate-500 mb-1">Event payload</div>
            <pre className="text-xs bg-slate-950/40 border border-slate-800 rounded p-2 whitespace-pre-wrap overflow-x-auto">
              {prettyJSON(delivery.event_payload)}
            </pre>
          </div>
          <div>
            <div className="text-xs uppercase text-slate-500 mb-1">Rendered payload</div>
            <pre className="text-xs bg-slate-950/40 border border-slate-800 rounded p-2 whitespace-pre-wrap overflow-x-auto">
              {delivery.rendered_payload}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}

function prettyJSON(s: string) {
  try {
    return JSON.stringify(JSON.parse(s), null, 2);
  } catch {
    return s;
  }
}

// ---------- Devices tab ----------

function DevicesTab() {
  const toasts = useToasts();
  const [subs, setSubs] = useState<PushSupport[] | null>(null);
  type PushSupport = PushSubscription;
  const [err, setErr] = useState<string | null>(null);
  const support = useMemo(() => pushSupport(), []);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const r = await api.listPushSubscriptions();
      setSubs(r);
      setErr(null);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'load failed');
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function onEnable() {
    setBusy(true);
    try {
      await subscribeToPush();
      toasts.push('this device is now subscribed', 'success');
      await refresh();
    } catch (e) {
      toasts.push(e instanceof Error ? e.message : 'subscribe failed', 'error');
    } finally {
      setBusy(false);
    }
  }

  async function onUnsub(s: PushSubscription) {
    try {
      await unsubscribeFromPush(s.endpoint);
      toasts.push('unsubscribed', 'success');
      await refresh();
    } catch (e) {
      toasts.push(e instanceof Error ? e.message : 'unsubscribe failed', 'error');
    }
  }

  return (
    <>
      {err && <ErrorBar msg={err} />}
      {!support.httpsOk && (
        <div className="mb-4 flex items-start gap-2 px-3 py-2 rounded bg-amber-950/40 border border-amber-900 text-amber-200 text-sm">
          <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <span>
            Browser Push requires HTTPS. This will work once the panel is served behind
            Caddy with TLS; until then you can register a subscription from a browser
            that reaches the panel over https / localhost.
          </span>
        </div>
      )}
      {!support.supported && (
        <div className="mb-4 flex items-start gap-2 px-3 py-2 rounded bg-red-950/40 border border-red-900 text-red-200 text-sm">
          <XCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <span>Your browser does not support Web Push (no ServiceWorker / PushManager).</span>
        </div>
      )}
      <div className="mb-4">
        <button
          type="button"
          onClick={onEnable}
          disabled={busy || !support.supported || !support.httpsOk}
          className="flex items-center gap-2 px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 disabled:cursor-not-allowed text-sm font-medium"
        >
          <Monitor className="w-4 h-4" /> Enable push on this device
        </button>
      </div>
      {subs === null ? (
        <Loading />
      ) : subs.length === 0 ? (
        <Empty msg="No push subscriptions registered for your user." />
      ) : (
        <table className="w-full text-sm">
          <thead className="text-slate-400 uppercase text-xs tracking-wide">
            <tr>
              <th className="text-left px-2 py-1">User agent</th>
              <th className="text-left px-2 py-1">Endpoint</th>
              <th className="text-left px-2 py-1">Since</th>
              <th className="text-right px-2 py-1">Actions</th>
            </tr>
          </thead>
          <tbody>
            {(subs as PushSubscription[]).map((s) => (
              <tr key={s.id} className="border-t border-slate-800">
                <td className="px-2 py-2 text-xs truncate max-w-[220px]">{s.user_agent}</td>
                <td className="px-2 py-2 text-xs font-mono truncate max-w-[280px] text-slate-500">
                  {s.endpoint}
                </td>
                <td className="px-2 py-2 text-xs text-slate-500">
                  {new Date(s.created_at).toLocaleString()}
                </td>
                <td className="px-2 py-2 text-right">
                  <IconBtn label="unsubscribe" danger onClick={() => onUnsub(s)}>
                    <Trash2 className="w-3.5 h-3.5" />
                  </IconBtn>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

// ---------- Shared bits ----------

function IconBtn({
  children,
  label,
  danger,
  onClick,
}: {
  children: React.ReactNode;
  label: string;
  danger?: boolean;
  onClick: (e: React.MouseEvent) => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={label}
      title={label}
      className={`p-1.5 rounded border border-slate-700 hover:bg-slate-800 mr-1 ${
        danger ? 'text-red-400 hover:text-red-300' : 'text-slate-300'
      }`}
    >
      {children}
    </button>
  );
}

function Loading() {
  return <div className="text-slate-500 text-sm">loading...</div>;
}

function Empty({ msg }: { msg: string }) {
  return (
    <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60 text-slate-500 text-sm flex items-center gap-2">
      <CheckCircle className="w-4 h-4" /> {msg}
    </div>
  );
}

function ErrorBar({ msg }: { msg: string }) {
  return (
    <div className="mb-4 px-3 py-2 rounded bg-red-950/40 border border-red-900 text-sm text-red-300">
      {msg}
    </div>
  );
}
