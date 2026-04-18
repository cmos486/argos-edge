import { FormEvent, useEffect, useState } from 'react';
import { Plus, Trash2 } from 'lucide-react';
import {
  ActionType,
  ApiError,
  HeaderMode,
  MatcherType,
  Rule,
  RuleInput,
  TargetGroup,
  api,
} from '../api/client';
import Modal from './Modal';
import { useToasts } from './toastsContext';

type MatcherDraft =
  | { type: 'path'; patterns: string[] }
  | { type: 'path_exact'; values: string[] }
  | { type: 'method'; methods: string[] }
  | { type: 'header'; name: string; value: string; mode: HeaderMode }
  | { type: 'query'; name: string; value: string }
  | { type: 'remote_ip'; ranges: string[]; negate: boolean }
  | { type: 'host_header'; values: string[] };

interface ActionDraft {
  type: ActionType;
  target_group_id?: number;
  status_code?: number;
  target?: string;
  strip_query?: boolean;
  body?: string;
  content_type?: string;
  path?: string;
  strip_prefix?: string;
  query?: string;
}

interface FormDraft {
  name: string;
  priority: number;
  enabled: boolean;
  matchers: MatcherDraft[];
  action: ActionDraft;
}

function emptyDraft(): FormDraft {
  return {
    name: '',
    priority: 0,
    enabled: true,
    matchers: [],
    action: { type: 'forward' },
  };
}

function fromRule(rule: Rule): FormDraft {
  const d = emptyDraft();
  d.name = rule.name;
  d.priority = rule.priority;
  d.enabled = rule.enabled;
  d.matchers = rule.matchers.map((m) => matcherFromEnv(m));
  d.action = actionFromEnv(rule.action);
  return d;
}

function matcherFromEnv(m: { type: MatcherType; config: unknown }): MatcherDraft {
  const c = (m.config ?? {}) as Record<string, unknown>;
  switch (m.type) {
    case 'path':
      return { type: 'path', patterns: (c.patterns as string[]) ?? [] };
    case 'path_exact':
      return { type: 'path_exact', values: (c.values as string[]) ?? [] };
    case 'method':
      return { type: 'method', methods: (c.methods as string[]) ?? [] };
    case 'header':
      return {
        type: 'header',
        name: (c.name as string) ?? '',
        value: (c.value as string) ?? '',
        mode: ((c.mode as HeaderMode) ?? 'exact') as HeaderMode,
      };
    case 'query':
      return {
        type: 'query',
        name: (c.name as string) ?? '',
        value: (c.value as string) ?? '',
      };
    case 'remote_ip':
      return {
        type: 'remote_ip',
        ranges: (c.ranges as string[]) ?? [],
        negate: (c.negate as boolean) ?? false,
      };
    case 'host_header':
      return { type: 'host_header', values: (c.values as string[]) ?? [] };
  }
}

function actionFromEnv(a: { type: ActionType; config: unknown }): ActionDraft {
  const c = (a.config ?? {}) as Record<string, unknown>;
  switch (a.type) {
    case 'forward':
      return { type: 'forward', target_group_id: c.target_group_id as number };
    case 'redirect':
      return {
        type: 'redirect',
        status_code: (c.status_code as number) ?? 301,
        target: (c.target as string) ?? '',
        strip_query: (c.strip_query as boolean) ?? false,
      };
    case 'fixed_response':
      return {
        type: 'fixed_response',
        status_code: (c.status_code as number) ?? 200,
        body: (c.body as string) ?? '',
        content_type: (c.content_type as string) ?? 'text/plain; charset=utf-8',
      };
    case 'block':
      return { type: 'block' };
    case 'rewrite':
      return {
        type: 'rewrite',
        path: (c.path as string) ?? '',
        strip_prefix: (c.strip_prefix as string) ?? '',
        query: (c.query as string) ?? '',
      };
  }
}

function toRuleInput(draft: FormDraft): RuleInput {
  const matchers = draft.matchers.map((m) => {
    switch (m.type) {
      case 'path':
        return { type: 'path' as MatcherType, config: { patterns: m.patterns } };
      case 'path_exact':
        return { type: 'path_exact' as MatcherType, config: { values: m.values } };
      case 'method':
        return { type: 'method' as MatcherType, config: { methods: m.methods } };
      case 'header':
        return {
          type: 'header' as MatcherType,
          config: { name: m.name, value: m.value, mode: m.mode },
        };
      case 'query':
        return { type: 'query' as MatcherType, config: { name: m.name, value: m.value } };
      case 'remote_ip':
        return {
          type: 'remote_ip' as MatcherType,
          config: { ranges: m.ranges, negate: m.negate },
        };
      case 'host_header':
        return { type: 'host_header' as MatcherType, config: { values: m.values } };
    }
  });

  let action: RuleInput['action'];
  switch (draft.action.type) {
    case 'forward':
      action = {
        type: 'forward',
        config: { target_group_id: draft.action.target_group_id ?? 0 },
      };
      break;
    case 'redirect':
      action = {
        type: 'redirect',
        config: {
          status_code: draft.action.status_code ?? 301,
          target: draft.action.target ?? '',
          strip_query: draft.action.strip_query ?? false,
        },
      };
      break;
    case 'fixed_response':
      action = {
        type: 'fixed_response',
        config: {
          status_code: draft.action.status_code ?? 200,
          body: draft.action.body ?? '',
          content_type: draft.action.content_type ?? 'text/plain; charset=utf-8',
        },
      };
      break;
    case 'block':
      action = { type: 'block', config: {} };
      break;
    case 'rewrite':
      action = {
        type: 'rewrite',
        config: {
          path: draft.action.path ?? '',
          strip_prefix: draft.action.strip_prefix ?? '',
          query: draft.action.query ?? '',
        },
      };
      break;
  }

  return {
    name: draft.name,
    priority: draft.priority || undefined,
    action,
    matchers,
  };
}

interface Props {
  open: boolean;
  hostId: number;
  tgs: TargetGroup[];
  editing: Rule | null;
  onClose: () => void;
  onSaved: () => void;
}

export default function RuleFormModal({ open, hostId, tgs, editing, onClose, onSaved }: Props) {
  const toasts = useToasts();
  const [draft, setDraft] = useState<FormDraft>(emptyDraft());
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setDraft(editing ? fromRule(editing) : emptyDraft());
      setError(null);
    }
  }, [open, editing]);

  function patchAction(p: Partial<ActionDraft>) {
    setDraft({ ...draft, action: { ...draft.action, ...p } });
  }

  function addMatcher(type: MatcherType) {
    const m: MatcherDraft =
      type === 'path' ? { type: 'path', patterns: [''] }
      : type === 'path_exact' ? { type: 'path_exact', values: [''] }
      : type === 'method' ? { type: 'method', methods: ['GET'] }
      : type === 'header' ? { type: 'header', name: '', value: '', mode: 'exact' }
      : type === 'query' ? { type: 'query', name: '', value: '' }
      : type === 'remote_ip' ? { type: 'remote_ip', ranges: [''], negate: false }
      : { type: 'host_header', values: [''] };
    setDraft({ ...draft, matchers: [...draft.matchers, m] });
  }

  function updateMatcher(i: number, next: MatcherDraft) {
    const ms = draft.matchers.slice();
    ms[i] = next;
    setDraft({ ...draft, matchers: ms });
  }
  function removeMatcher(i: number) {
    setDraft({ ...draft, matchers: draft.matchers.filter((_, j) => j !== i) });
  }

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const payload = toRuleInput(draft);
      if (editing) {
        await api.updateRule(hostId, editing.id, { ...payload, enabled: draft.enabled });
        toasts.push('rule updated', 'success');
      } else {
        await api.createRule(hostId, payload);
        toasts.push('rule created', 'success');
      }
      onSaved();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'save failed');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Modal open={open} title={editing ? `Edit rule #${editing.id}` : 'Add rule'} onClose={onClose}>
      <form onSubmit={onSubmit} className="space-y-4 text-sm">
        <div className="grid grid-cols-3 gap-3">
          <div className="col-span-2">
            <label className="block text-slate-300 mb-1">Name (optional)</label>
            <input
              type="text"
              value={draft.name}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              className={inputCls}
              placeholder="api routes"
            />
          </div>
          <div>
            <label className="block text-slate-300 mb-1">Priority</label>
            <input
              type="number"
              min={0}
              max={50000}
              value={draft.priority}
              onChange={(e) => setDraft({ ...draft, priority: parseInt(e.target.value, 10) || 0 })}
              className={inputCls + ' font-mono'}
              placeholder="auto"
            />
            <p className="text-xs text-slate-500 mt-1">0 = auto assign (max+10)</p>
          </div>
        </div>

        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="text-slate-300 uppercase text-xs tracking-wide">Matchers (AND)</span>
            <MatcherPicker onPick={addMatcher} />
          </div>
          {draft.matchers.length === 0 && (
            <p className="text-xs text-slate-500">
              Add at least one matcher so the rule has a condition to fire on.
            </p>
          )}
          <div className="space-y-2">
            {draft.matchers.map((m, i) => (
              <MatcherRow
                key={i}
                matcher={m}
                onChange={(next) => updateMatcher(i, next)}
                onRemove={() => removeMatcher(i)}
              />
            ))}
          </div>
        </div>

        <div>
          <label className="block text-slate-300 mb-1">Action</label>
          <select
            value={draft.action.type}
            onChange={(e) => patchAction({ type: e.target.value as ActionType })}
            className={inputCls}
          >
            <option value="forward">forward</option>
            <option value="redirect">redirect</option>
            <option value="fixed_response">fixed_response</option>
            <option value="block">block</option>
            <option value="rewrite">rewrite</option>
          </select>
          <div className="mt-3 p-3 rounded border border-slate-800 bg-slate-950/60">
            <ActionEditor action={draft.action} onChange={patchAction} tgs={tgs} />
          </div>
        </div>

        {editing && (
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={draft.enabled}
              onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })}
              className="w-4 h-4 accent-sky-600"
            />
            <span>Enabled</span>
          </label>
        )}

        {error && (
          <div className="px-3 py-2 rounded bg-red-950/40 border border-red-900 text-red-300">
            {error}
          </div>
        )}

        <div className="flex justify-end gap-2 pt-1">
          <button type="button" onClick={onClose} className="px-3 py-1.5 rounded border border-slate-700 hover:bg-slate-800">
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

function MatcherPicker({ onPick }: { onPick: (t: MatcherType) => void }) {
  const [open, setOpen] = useState(false);
  const types: { t: MatcherType; label: string }[] = [
    { t: 'path', label: 'Path (glob)' },
    { t: 'path_exact', label: 'Path (exact)' },
    { t: 'method', label: 'Method' },
    { t: 'header', label: 'Header' },
    { t: 'query', label: 'Query param' },
    { t: 'remote_ip', label: 'Remote IP' },
    { t: 'host_header', label: 'Host header' },
  ];
  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1 px-2 py-1 rounded border border-slate-700 hover:bg-slate-800 text-xs"
      >
        <Plus className="w-3 h-3" /> Add matcher
      </button>
      {open && (
        <div className="absolute right-0 mt-1 w-56 bg-slate-900 border border-slate-700 rounded shadow-lg z-10">
          {types.map((it) => (
            <button
              key={it.t}
              type="button"
              onClick={() => {
                onPick(it.t);
                setOpen(false);
              }}
              className="w-full text-left px-3 py-1.5 hover:bg-slate-800 text-xs"
            >
              {it.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function MatcherRow({
  matcher,
  onChange,
  onRemove,
}: {
  matcher: MatcherDraft;
  onChange: (m: MatcherDraft) => void;
  onRemove: () => void;
}) {
  return (
    <div className="p-3 rounded border border-slate-800 bg-slate-950/40">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs uppercase text-slate-400 tracking-wide">{matcher.type}</span>
        <button
          type="button"
          onClick={onRemove}
          className="text-xs px-1.5 py-0.5 rounded border border-slate-700 text-red-400 hover:bg-slate-800"
        >
          <Trash2 className="w-3 h-3" />
        </button>
      </div>
      <MatcherBody matcher={matcher} onChange={onChange} />
    </div>
  );
}

function MatcherBody({ matcher, onChange }: { matcher: MatcherDraft; onChange: (m: MatcherDraft) => void }) {
  switch (matcher.type) {
    case 'path':
      return (
        <StringList
          value={matcher.patterns}
          onChange={(patterns) => onChange({ ...matcher, patterns })}
          placeholder="/api/*"
        />
      );
    case 'path_exact':
      return (
        <StringList
          value={matcher.values}
          onChange={(values) => onChange({ ...matcher, values })}
          placeholder="/exact/path"
        />
      );
    case 'method': {
      const all = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
      return (
        <div className="flex flex-wrap gap-2">
          {all.map((m) => {
            const on = matcher.methods.includes(m);
            return (
              <button
                type="button"
                key={m}
                onClick={() => {
                  const methods = on ? matcher.methods.filter((x) => x !== m) : [...matcher.methods, m];
                  onChange({ ...matcher, methods });
                }}
                className={`px-2 py-0.5 rounded text-xs border ${
                  on ? 'bg-sky-900 border-sky-700 text-sky-200' : 'border-slate-700 text-slate-400'
                }`}
              >
                {m}
              </button>
            );
          })}
        </div>
      );
    }
    case 'header':
      return (
        <div className="grid grid-cols-3 gap-2">
          <input
            className={inputCls + ' font-mono'}
            placeholder="Header-Name"
            value={matcher.name}
            onChange={(e) => onChange({ ...matcher, name: e.target.value })}
          />
          <input
            className={inputCls + ' font-mono'}
            placeholder="value"
            value={matcher.value}
            onChange={(e) => onChange({ ...matcher, value: e.target.value })}
          />
          <select
            className={inputCls}
            value={matcher.mode}
            onChange={(e) => onChange({ ...matcher, mode: e.target.value as HeaderMode })}
          >
            <option value="exact">exact</option>
            <option value="regex">regex</option>
          </select>
        </div>
      );
    case 'query':
      return (
        <div className="grid grid-cols-2 gap-2">
          <input
            className={inputCls + ' font-mono'}
            placeholder="param"
            value={matcher.name}
            onChange={(e) => onChange({ ...matcher, name: e.target.value })}
          />
          <input
            className={inputCls + ' font-mono'}
            placeholder="value"
            value={matcher.value}
            onChange={(e) => onChange({ ...matcher, value: e.target.value })}
          />
        </div>
      );
    case 'remote_ip':
      return (
        <div className="space-y-2">
          <StringList
            value={matcher.ranges}
            onChange={(ranges) => onChange({ ...matcher, ranges })}
            placeholder="192.168.0.0/16 or 10.0.0.1"
          />
          <label className="flex items-center gap-2 text-xs">
            <input
              type="checkbox"
              checked={matcher.negate}
              onChange={(e) => onChange({ ...matcher, negate: e.target.checked })}
              className="w-4 h-4 accent-sky-600"
            />
            Negate (match when source is NOT in these ranges)
          </label>
        </div>
      );
    case 'host_header':
      return (
        <StringList
          value={matcher.values}
          onChange={(values) => onChange({ ...matcher, values })}
          placeholder="alt.example.com"
        />
      );
  }
}

function StringList({
  value,
  onChange,
  placeholder,
}: {
  value: string[];
  onChange: (v: string[]) => void;
  placeholder?: string;
}) {
  return (
    <div className="space-y-1">
      {value.map((v, i) => (
        <div key={i} className="flex items-center gap-2">
          <input
            className={inputCls + ' font-mono flex-1'}
            placeholder={placeholder}
            value={v}
            onChange={(e) => {
              const next = value.slice();
              next[i] = e.target.value;
              onChange(next);
            }}
          />
          <button
            type="button"
            onClick={() => onChange(value.filter((_, j) => j !== i))}
            className="text-xs px-2 py-1 rounded border border-slate-700 text-red-400 hover:bg-slate-800"
          >
            x
          </button>
        </div>
      ))}
      <button
        type="button"
        onClick={() => onChange([...value, ''])}
        className="text-xs px-2 py-0.5 rounded border border-slate-700 hover:bg-slate-800"
      >
        + Add
      </button>
    </div>
  );
}

function ActionEditor({
  action,
  onChange,
  tgs,
}: {
  action: ActionDraft;
  onChange: (p: Partial<ActionDraft>) => void;
  tgs: TargetGroup[];
}) {
  switch (action.type) {
    case 'forward':
      return (
        <div>
          <label className="block text-slate-300 mb-1">Target group</label>
          <select
            value={action.target_group_id ?? 0}
            onChange={(e) => onChange({ target_group_id: parseInt(e.target.value, 10) })}
            className={inputCls}
          >
            <option value={0}>-- select --</option>
            {tgs.map((tg) => (
              <option key={tg.id} value={tg.id}>
                {tg.name} ({tg.protocol} / {tg.algorithm})
              </option>
            ))}
          </select>
        </div>
      );
    case 'redirect':
      return (
        <div className="space-y-2">
          <div className="grid grid-cols-4 gap-2">
            <div>
              <label className="block text-slate-300 mb-1">Status</label>
              <select
                value={action.status_code ?? 301}
                onChange={(e) => onChange({ status_code: parseInt(e.target.value, 10) })}
                className={inputCls}
              >
                <option value={301}>301</option>
                <option value={302}>302</option>
                <option value={307}>307</option>
                <option value={308}>308</option>
              </select>
            </div>
            <div className="col-span-3">
              <label className="block text-slate-300 mb-1">Target</label>
              <input
                className={inputCls + ' font-mono'}
                value={action.target ?? ''}
                onChange={(e) => onChange({ target: e.target.value })}
                placeholder="https://{http.request.host}/new{http.request.uri.path}"
              />
            </div>
          </div>
          <p className="text-xs text-slate-500">
            Placeholders supported: <code>{'{http.request.host}'}</code>,{' '}
            <code>{'{http.request.uri.path}'}</code>, <code>{'{http.request.uri.query}'}</code>.
          </p>
          <label className="flex items-center gap-2 text-xs">
            <input
              type="checkbox"
              checked={action.strip_query ?? false}
              onChange={(e) => onChange({ strip_query: e.target.checked })}
              className="w-4 h-4 accent-sky-600"
            />
            Strip query string (ensure target does not include a query)
          </label>
        </div>
      );
    case 'fixed_response':
      return (
        <div className="space-y-2">
          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="block text-slate-300 mb-1">Status</label>
              <input
                type="number"
                min={100}
                max={599}
                className={inputCls + ' font-mono'}
                value={action.status_code ?? 200}
                onChange={(e) => onChange({ status_code: parseInt(e.target.value, 10) })}
              />
            </div>
            <div>
              <label className="block text-slate-300 mb-1">Content-Type</label>
              <input
                type="text"
                className={inputCls + ' font-mono'}
                value={action.content_type ?? 'text/plain; charset=utf-8'}
                onChange={(e) => onChange({ content_type: e.target.value })}
                placeholder="text/plain; charset=utf-8"
              />
            </div>
          </div>
          <div>
            <label className="block text-slate-300 mb-1">Body</label>
            <textarea
              rows={6}
              className={inputCls + ' font-mono'}
              value={action.body ?? ''}
              onChange={(e) => onChange({ body: e.target.value })}
              placeholder="HTML allowed; you are responsible for the content."
            />
          </div>
        </div>
      );
    case 'block':
      return <p className="text-xs text-slate-400">Responds with HTTP 403 and an empty body.</p>;
    case 'rewrite':
      return (
        <div className="space-y-2">
          <div>
            <label className="block text-slate-300 mb-1">Path (optional)</label>
            <input
              className={inputCls + ' font-mono'}
              value={action.path ?? ''}
              onChange={(e) => onChange({ path: e.target.value })}
              placeholder="/new"
            />
          </div>
          <div>
            <label className="block text-slate-300 mb-1">Strip prefix (optional)</label>
            <input
              className={inputCls + ' font-mono'}
              value={action.strip_prefix ?? ''}
              onChange={(e) => onChange({ strip_prefix: e.target.value })}
              placeholder="/v1"
            />
          </div>
          <div>
            <label className="block text-slate-300 mb-1">Query (optional)</label>
            <input
              className={inputCls + ' font-mono'}
              value={action.query ?? ''}
              onChange={(e) => onChange({ query: e.target.value })}
              placeholder="foo=bar"
            />
          </div>
          <p className="text-xs text-slate-500">
            At least one of the three must be set. The request continues to the host&apos;s default target group after the rewrite.
          </p>
        </div>
      );
  }
}

const inputCls =
  'w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500';
