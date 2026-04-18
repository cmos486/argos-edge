import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  DndContext,
  DragEndEvent,
  PointerSensor,
  closestCenter,
  useSensor,
  useSensors,
} from '@dnd-kit/core';
import {
  SortableContext,
  arrayMove,
  useSortable,
  verticalListSortingStrategy,
} from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import { GripVertical, Pencil, Plus, Power, Trash2 } from 'lucide-react';
import {
  ApiError,
  Host,
  Rule,
  TargetGroup,
  api,
} from '../api/client';
import RuleFormModal from '../components/RuleFormModal';
import { useToasts } from '../components/toastsContext';

export default function Rules() {
  const { id } = useParams();
  const hostId = Number(id);
  const toasts = useToasts();

  const [host, setHost] = useState<Host | null>(null);
  const [tgs, setTgs] = useState<TargetGroup[]>([]);
  const [rules, setRules] = useState<Rule[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<Rule | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [h, r, t] = await Promise.all([
        api.listHosts(),
        api.listRules(hostId),
        api.listTargetGroups(),
      ]);
      setHost(h.find((x) => x.id === hostId) ?? null);
      setRules(r);
      setTgs(t);
      setErr(null);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'load failed');
    }
  }, [hostId]);

  useEffect(() => {
    if (!Number.isFinite(hostId) || hostId <= 0) return;
    refresh();
  }, [hostId, refresh]);

  const sensors = useSensors(useSensor(PointerSensor, { activationConstraint: { distance: 5 } }));

  async function onDragEnd(e: DragEndEvent) {
    if (!rules) return;
    const { active, over } = e;
    if (!over || active.id === over.id) return;
    const oldIndex = rules.findIndex((r) => String(r.id) === String(active.id));
    const newIndex = rules.findIndex((r) => String(r.id) === String(over.id));
    if (oldIndex < 0 || newIndex < 0) return;
    const reordered = arrayMove(rules, oldIndex, newIndex);
    setRules(reordered); // optimistic
    try {
      const fresh = await api.reorderRules(hostId, reordered.map((r) => r.id));
      setRules(fresh);
      toasts.push('priorities updated', 'success');
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'reorder failed', 'error');
      refresh();
    }
  }

  async function onToggle(rule: Rule) {
    try {
      await api.toggleRule(hostId, rule.id);
      await refresh();
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'toggle failed', 'error');
    }
  }
  async function onDelete(rule: Rule) {
    if (!window.confirm(`Delete rule #${rule.id}?`)) return;
    try {
      await api.deleteRule(hostId, rule.id);
      toasts.push(`deleted rule ${rule.id}`, 'success');
      await refresh();
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'delete failed', 'error');
    }
  }

  if (!Number.isFinite(hostId) || hostId <= 0) {
    return <div className="p-6 text-red-400">invalid host id</div>;
  }

  const defaultTG = host && tgs.find((t) => t.id === host.target_group_id);

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <nav className="text-sm text-slate-400 mb-3">
        <Link to="/hosts" className="hover:text-slate-200">Hosts</Link>
        <span className="mx-2">/</span>
        {host ? <span className="text-slate-200 font-mono">{host.domain}</span> : '...'}
        <span className="mx-2">/</span>
        <span className="text-slate-200">Rules</span>
      </nav>

      {err && (
        <div className="mb-4 px-3 py-2 rounded bg-red-950/40 border border-red-900 text-sm text-red-300">
          {err}
        </div>
      )}

      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-semibold">Rules</h1>
        <button
          type="button"
          onClick={() => {
            setEditing(null);
            setModalOpen(true);
          }}
          className="flex items-center gap-2 px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 text-sm font-medium"
        >
          <Plus className="w-4 h-4" />
          Add rule
        </button>
      </div>

      {defaultTG && (
        <div className="mb-4 p-3 rounded-lg border border-slate-800 bg-slate-900 text-sm">
          <div className="text-xs uppercase text-slate-500 tracking-wide mb-1">Default action</div>
          <div className="flex items-center gap-2">
            <span className="text-slate-300">forward to</span>
            <Link to={`/target-groups/${defaultTG.id}`} className="font-mono text-sky-400 hover:underline">
              {defaultTG.name}
            </Link>
            <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300">
              {defaultTG.protocol}
            </span>
            <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300">
              {defaultTG.algorithm}
            </span>
            <span className="text-xs text-slate-500">
              {defaultTG.targets_enabled_count}/{defaultTG.targets_count} targets
            </span>
          </div>
          <p className="mt-2 text-xs text-slate-500">
            Edit on the host itself to change. Rules below are evaluated in priority order (lower first); first match wins and is terminal.
          </p>
        </div>
      )}

      {rules === null ? (
        <div className="text-slate-500 text-sm">loading...</div>
      ) : rules.length === 0 ? (
        <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60 text-slate-500 text-sm">
          No rules. Requests will always go to the default action.
        </div>
      ) : (
        <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={onDragEnd}>
          <SortableContext items={rules.map((r) => r.id)} strategy={verticalListSortingStrategy}>
            <div className="space-y-2">
              {rules.map((rule) => (
                <SortableRule
                  key={rule.id}
                  rule={rule}
                  tgs={tgs}
                  onEdit={() => {
                    setEditing(rule);
                    setModalOpen(true);
                  }}
                  onToggle={() => onToggle(rule)}
                  onDelete={() => onDelete(rule)}
                />
              ))}
            </div>
          </SortableContext>
        </DndContext>
      )}

      <RuleFormModal
        open={modalOpen}
        hostId={hostId}
        tgs={tgs}
        editing={editing}
        onClose={() => setModalOpen(false)}
        onSaved={async () => {
          setModalOpen(false);
          await refresh();
        }}
      />
    </div>
  );
}

function SortableRule({
  rule,
  tgs,
  onEdit,
  onToggle,
  onDelete,
}: {
  rule: Rule;
  tgs: TargetGroup[];
  onEdit: () => void;
  onToggle: () => void;
  onDelete: () => void;
}) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({
    id: rule.id,
  });
  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.7 : 1,
  };

  const actionColor: Record<string, string> = {
    forward: 'bg-sky-900 text-sky-200 border-sky-800',
    redirect: 'bg-amber-900 text-amber-200 border-amber-800',
    fixed_response: 'bg-purple-900 text-purple-200 border-purple-800',
    block: 'bg-red-900 text-red-200 border-red-800',
    rewrite: 'bg-teal-900 text-teal-200 border-teal-800',
  };
  const enabledCls = rule.enabled
    ? 'bg-emerald-900 text-emerald-200'
    : 'bg-slate-800 text-slate-400';

  return (
    <div
      ref={setNodeRef}
      style={style}
      className={`flex items-center gap-3 p-3 rounded-lg border ${
        rule.enabled ? 'border-slate-800 bg-slate-900' : 'border-slate-800 bg-slate-900/40'
      }`}
    >
      <button
        type="button"
        className="p-1 text-slate-500 hover:text-slate-300 cursor-grab active:cursor-grabbing"
        {...attributes}
        {...listeners}
        title="drag to reorder"
        aria-label="drag handle"
      >
        <GripVertical className="w-4 h-4" />
      </button>
      <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono min-w-[44px] text-center">
        {rule.priority}
      </span>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          {rule.name && <span className="font-medium text-slate-200">{rule.name}</span>}
          <span className={`text-xs px-2 py-0.5 rounded border ${actionColor[rule.action.type] ?? 'border-slate-700 text-slate-300'}`}>
            {rule.action.type}
          </span>
          <span className={`text-xs px-2 py-0.5 rounded ${enabledCls}`}>
            {rule.enabled ? 'on' : 'off'}
          </span>
        </div>
        <div className="text-xs text-slate-400 mt-1 font-mono truncate">
          {summarizeMatchers(rule)} <span className="text-slate-600">→</span> {summarizeAction(rule, tgs)}
        </div>
      </div>
      <div className="flex items-center gap-1">
        <IconButton label="toggle" onClick={onToggle}><Power className="w-4 h-4" /></IconButton>
        <IconButton label="edit" onClick={onEdit}><Pencil className="w-4 h-4" /></IconButton>
        <IconButton label="delete" onClick={onDelete} danger><Trash2 className="w-4 h-4" /></IconButton>
      </div>
    </div>
  );
}

function summarizeMatchers(rule: Rule): string {
  return rule.matchers
    .map((m) => {
      const c = (m.config ?? {}) as Record<string, unknown>;
      switch (m.type) {
        case 'path':
          return `path=${(c.patterns as string[])?.join('|') ?? ''}`;
        case 'path_exact':
          return `path==${(c.values as string[])?.join('|') ?? ''}`;
        case 'method':
          return `method IN [${(c.methods as string[])?.join(',') ?? ''}]`;
        case 'header':
          return `header[${c.name}]=${c.value} (${c.mode})`;
        case 'query':
          return `query[${c.name}]=${c.value}`;
        case 'remote_ip':
          return `remote_ip${c.negate ? ' NOT' : ''} IN [${(c.ranges as string[])?.join(',') ?? ''}]`;
        case 'host_header':
          return `host=${(c.values as string[])?.join('|') ?? ''}`;
        default:
          return String(m.type);
      }
    })
    .join(' AND ');
}

function summarizeAction(rule: Rule, tgs: TargetGroup[]): string {
  const c = (rule.action.config ?? {}) as Record<string, unknown>;
  switch (rule.action.type) {
    case 'forward': {
      const tg = tgs.find((t) => t.id === (c.target_group_id as number));
      return `forward → ${tg ? tg.name : `tg#${c.target_group_id}`}`;
    }
    case 'redirect':
      return `${c.status_code} Location: ${c.target}`;
    case 'fixed_response':
      return `${c.status_code} ${c.content_type}`;
    case 'block':
      return '403';
    case 'rewrite':
      return `rewrite${c.path ? ` path=${c.path}` : ''}${c.strip_prefix ? ` strip_prefix=${c.strip_prefix}` : ''}${c.query ? ` query=${c.query}` : ''} → default`;
    default:
      return String(rule.action.type);
  }
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
