import React, { useEffect, useState, useMemo } from 'react';
import { getAuditEvents } from '../services/api';
import {
  Clock,
  Filter,
  AlertCircle,
  Search,
  ShieldAlert,
  ShieldCheck,
  Shield,
  Layers,
  ChevronDown,
  ChevronUp,
  Cpu,
  Hash,
  Activity,
  ArrowUpDown
} from 'lucide-react';
import type { SecurityDecision } from '../types';

export const AuditTrail: React.FC = () => {
  const [events, setEvents] = useState<SecurityDecision[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [decisionFilter, setDecisionFilter] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [sortOrder, setSortOrder] = useState<"desc" | "asc">("desc");
  const [expandedEvents, setExpandedEvents] = useState<Record<string, boolean>>({});

  useEffect(() => {
    let isMounted = true;
    getAuditEvents()
      .then(data => {
        if (isMounted) {
          setEvents(data);
          setLoading(false);
        }
      })
      .catch(err => {
        if (isMounted) {
          setError(err.message || "Failed to load audit events.");
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, []);

  const toggleExpand = (id: string) => {
    setExpandedEvents(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const counts = useMemo(() => {
    const total = events.length;
    let allowed = 0;
    let blocked = 0;
    let approvals = 0;
    for (const e of events) {
      if (e.final_decision === 'ALLOW') allowed++;
      else if (e.final_decision === 'BLOCK') blocked++;
      else if (e.final_decision === 'REQUIRE_APPROVAL') approvals++;
    }
    return { total, allowed, blocked, approvals };
  }, [events]);

  const filteredEvents = useMemo(() => {
    const query = searchQuery.toLowerCase().trim();
    const result = events.filter(e => {
      if (decisionFilter !== "ALL" && e.final_decision !== decisionFilter) {
        return false;
      }
      if (!query) return true;
      return (
        e.operation?.toLowerCase().includes(query) ||
        e.reason?.toLowerCase().includes(query) ||
        e.agent_id?.toLowerCase().includes(query) ||
        e.event_id?.toLowerCase().includes(query) ||
        e.replay?.request_id?.toLowerCase().includes(query)
      );
    });

    return result.sort((a, b) => {
      const timeA = new Date(a.timestamp).getTime();
      const timeB = new Date(b.timestamp).getTime();
      return sortOrder === "desc" ? timeB - timeA : timeA - timeB;
    });
  }, [events, decisionFilter, searchQuery, sortOrder]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-80 space-y-4">
        <div className="w-7 h-7 border-2 border-[#A2B89A] border-t-transparent rounded-full animate-spin"></div>
        <p className="text-[#A5A69C] font-mono text-xs tracking-wider animate-pulse uppercase">
          Querying immutable audit records (audit.db)...
        </p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-5xl mx-auto bg-[#C25D54]/10 border border-[#C25D54]/30 rounded-xl p-6 text-[#C25D54] space-y-2">
        <div className="flex items-center gap-2 font-bold text-sm">
          <AlertCircle size={18} /> Error Fetching Audit Trail
        </div>
        <p className="text-xs text-[#A5A69C]">{error}</p>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-[#262C24] pb-5">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-[9.5px] font-mono tracking-[0.22em] text-[#A2B89A] uppercase font-medium">
              IMMUTABLE AUDIT LOG
            </span>
            <span className="text-[#6F736A] text-xs font-mono">SQLite (audit.db)</span>
          </div>
          <h1 className="font-serif text-2xl lg:text-3xl font-normal text-[#F0EEE5] tracking-tight">Security Event Audit Trail</h1>
          <p className="text-[#A5A69C] text-xs mt-1">
            Chronological ledger of every gateway interception, multi-layer verification, and execution decision.
          </p>
        </div>

        {/* Aggregate Stats Badges */}
        <div className="flex items-center gap-2 font-mono text-xs">
          <div className="bg-[#191C18] border border-[#262C24] px-3 py-1.5 rounded-lg flex items-center gap-2">
            <span className="text-[#6F736A] uppercase text-[10px]">Total:</span>
            <span className="text-[#F0EEE5] font-bold">{counts.total}</span>
          </div>
          <div className="bg-[#191C18] border border-[#262C24] px-3 py-1.5 rounded-lg flex items-center gap-2">
            <span className="text-[#8FA887] uppercase text-[10px]">Allow:</span>
            <span className="text-[#8FA887] font-bold">{counts.allowed}</span>
          </div>
          <div className="bg-[#191C18] border border-[#262C24] px-3 py-1.5 rounded-lg flex items-center gap-2">
            <span className="text-[#C25D54] uppercase text-[10px]">Block:</span>
            <span className="text-[#C25D54] font-bold">{counts.blocked}</span>
          </div>
          <div className="bg-[#191C18] border border-[#262C24] px-3 py-1.5 rounded-lg flex items-center gap-2">
            <span className="text-[#D4A359] uppercase text-[10px]">Approval:</span>
            <span className="text-[#D4A359] font-bold">{counts.approvals}</span>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#191C18] border border-[#262C24] rounded-xl p-3 flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
        <div className="relative flex-1">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#6F736A]" />
          <input
            type="text"
            placeholder="Search by operation, reason, agent, event ID, or request ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 bg-[#141713] border border-[#262C24] rounded-lg text-xs text-[#F0EEE5] placeholder-[#6F736A] focus:outline-none focus:border-[#A2B89A] font-mono transition-colors"
          />
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <div className="flex items-center gap-1.5 bg-[#141713] border border-[#262C24] rounded-lg px-2.5 py-1">
            <Filter size={12} className="text-[#6F736A]" />
            <select
              value={decisionFilter}
              onChange={(e) => setDecisionFilter(e.target.value)}
              className="bg-transparent text-xs text-[#F0EEE5] font-mono focus:outline-none cursor-pointer"
            >
              <option value="ALL" className="bg-[#191C18] text-[#F0EEE5]">All Decisions ({events.length})</option>
              <option value="ALLOW" className="bg-[#191C18] text-[#8FA887]">ALLOW ({counts.allowed})</option>
              <option value="BLOCK" className="bg-[#191C18] text-[#C25D54]">BLOCK ({counts.blocked})</option>
              <option value="REQUIRE_APPROVAL" className="bg-[#191C18] text-[#D4A359]">APPROVAL ({counts.approvals})</option>
            </select>
          </div>

          <button
            onClick={() => setSortOrder(prev => prev === "desc" ? "asc" : "desc")}
            className="flex items-center gap-1.5 bg-[#141713] border border-[#262C24] hover:border-[#343B32] rounded-lg px-2.5 py-1 text-xs text-[#A5A69C] font-mono transition-colors"
            title="Toggle Sort Order"
          >
            <ArrowUpDown size={12} />
            <span>{sortOrder === "desc" ? "Newest First" : "Oldest First"}</span>
          </button>
        </div>
      </div>

      {/* Timeline Section */}
      <div className="relative border-l border-[#262C24] ml-4 md:ml-6 space-y-5 pb-8 pt-2">
        {filteredEvents.map((e) => {
          const isAllow = e.final_decision === 'ALLOW';
          const isBlock = e.final_decision === 'BLOCK';
          const isExpanded = !!expandedEvents[e.event_id];
          const hasArgs = e.arguments && Object.keys(e.arguments).length > 0;

          return (
            <div key={e.event_id} className="relative pl-6 md:pl-8 group">
              {/* Timeline Indicator Dot */}
              <div
                className={`absolute -left-[6px] top-4 w-3 h-3 rounded-full border-2 border-[#101210] transition-transform duration-150 group-hover:scale-125 ${
                  isAllow
                    ? 'bg-[#8FA887] ring-4 ring-[#8FA887]/15'
                    : isBlock
                    ? 'bg-[#C25D54] ring-4 ring-[#C25D54]/15'
                    : 'bg-[#D4A359] ring-4 ring-[#D4A359]/15'
                }`}
              />

              {/* Event Card */}
              <div className="bg-[#191C18] border border-[#262C24] hover:border-[#343B32] rounded-xl p-4 md:p-5 transition-all duration-150 space-y-3 shadow-sm">
                {/* Card Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span
                      className={`px-2.5 py-0.5 text-[11px] font-bold rounded font-mono tracking-wider border ${
                        isAllow
                          ? 'bg-[#8FA887]/10 text-[#8FA887] border-[#8FA887]/25'
                          : isBlock
                          ? 'bg-[#C25D54]/10 text-[#C25D54] border-[#C25D54]/25'
                          : 'bg-[#D4A359]/10 text-[#D4A359] border-[#D4A359]/25'
                      }`}
                    >
                      {e.final_decision}
                    </span>

                    <span className="text-[#F0EEE5] font-mono font-bold text-sm">
                      {e.operation}
                    </span>

                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                        e.downstream_executed
                          ? 'bg-[#8FA887]/10 text-[#8FA887] border-[#8FA887]/20'
                          : 'bg-[#141713] text-[#6F736A] border-[#262C24]'
                      }`}
                    >
                      {e.downstream_executed ? 'DOWNSTREAM EXECUTED' : 'DOWNSTREAM HALTED'}
                    </span>
                  </div>

                  <div className="flex items-center gap-1.5 text-[#6F736A] text-[11px] font-mono shrink-0">
                    <Clock size={12} className="text-[#A2B89A]" />
                    <span>{new Date(e.timestamp).toLocaleString()}</span>
                  </div>
                </div>

                {/* Reason Banner */}
                <div className="bg-[#141713] border border-[#262C24] rounded-lg p-3 text-xs flex items-start gap-2.5">
                  {isAllow ? (
                    <ShieldCheck size={15} className="text-[#8FA887] shrink-0 mt-0.5" />
                  ) : isBlock ? (
                    <ShieldAlert size={15} className="text-[#C25D54] shrink-0 mt-0.5" />
                  ) : (
                    <Shield size={15} className="text-[#D4A359] shrink-0 mt-0.5" />
                  )}
                  <div className="space-y-0.5 flex-1 min-w-0">
                    <div className="text-[10px] font-mono uppercase tracking-wider text-[#6F736A] font-semibold">
                      Enforcement Rationale
                    </div>
                    <div className="text-[#F0EEE5] font-mono text-xs break-words">
                      {e.reason || 'Decision reached via deterministic layer policy.'}
                    </div>
                  </div>
                </div>

                {/* Layer Verification Badges */}
                <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-1.5 text-[10px] font-mono pt-1">
                  <div className="bg-[#141713] border border-[#262C24] rounded p-1.5 text-center">
                    <div className="text-[#6F736A] text-[9px] uppercase">L1 Prov</div>
                    <div className="text-[#F0EEE5] font-bold truncate">
                      {e.provenance?.verification || 'HMAC OK'}
                    </div>
                  </div>
                  <div className="bg-[#141713] border border-[#262C24] rounded p-1.5 text-center">
                    <div className="text-[#6F736A] text-[9px] uppercase">L2 Replay</div>
                    <div className="text-[#F0EEE5] font-bold truncate">
                      {e.replay?.decision || 'UNIQUE'}
                    </div>
                  </div>
                  <div className="bg-[#141713] border border-[#262C24] rounded p-1.5 text-center">
                    <div className="text-[#6F736A] text-[9px] uppercase">L3 Cap</div>
                    <div className="text-[#F0EEE5] font-bold truncate">
                      {e.capability?.decision || 'CHECKED'}
                    </div>
                  </div>
                  <div className="bg-[#141713] border border-[#262C24] rounded p-1.5 text-center">
                    <div className="text-[#6F736A] text-[9px] uppercase">L4 Dest</div>
                    <div className="text-[#F0EEE5] font-bold truncate">
                      {e.destination?.trust || 'BOUND'}
                    </div>
                  </div>
                  <div className="bg-[#141713] border border-[#262C24] rounded p-1.5 text-center">
                    <div className="text-[#6F736A] text-[9px] uppercase">L5 Risk</div>
                    <div className="text-[#F0EEE5] font-bold truncate">
                      {e.risk?.level || 'EVALUATED'}
                    </div>
                  </div>
                  <div className="bg-[#141713] border border-[#262C24] rounded p-1.5 text-center">
                    <div className="text-[#6F736A] text-[9px] uppercase">L6 Context</div>
                    <div className="text-[#F0EEE5] font-bold truncate">
                      {e.context?.decision || 'VALID'}
                    </div>
                  </div>
                  <div className="bg-[#141713] border border-[#262C24] rounded p-1.5 text-center">
                    <div className="text-[#6F736A] text-[9px] uppercase">L7 Approval</div>
                    <div className="text-[#F0EEE5] font-bold truncate">
                      {e.approval?.status || 'N/A'}
                    </div>
                  </div>
                </div>

                {/* Metadata Ledger Row */}
                <div className="pt-2 border-t border-[#262C24] flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-[#6F736A]">
                  <div className="flex items-center gap-4 flex-wrap">
                    <span className="flex items-center gap-1">
                      <Hash size={11} className="text-[#A2B89A]" />
                      <span className="text-[#A5A69C]">{e.event_id}</span>
                    </span>
                    <span className="flex items-center gap-1">
                      <Cpu size={11} className="text-[#A2B89A]" />
                      <span className="text-[#A5A69C]">{e.agent_id}</span>
                    </span>
                    {e.replay?.request_id && (
                      <span className="flex items-center gap-1">
                        <Activity size={11} className="text-[#A2B89A]" />
                        <span className="text-[#6F736A]">Req:</span>
                        <span className="text-[#A5A69C] truncate max-w-[140px]" title={e.replay.request_id}>
                          {e.replay.request_id}
                        </span>
                      </span>
                    )}
                  </div>

                  {hasArgs && (
                    <button
                      onClick={() => toggleExpand(e.event_id)}
                      className="flex items-center gap-1 text-[#A2B89A] hover:text-[#D0DEC7] transition-colors py-0.5 px-1.5 rounded hover:bg-[#141713]"
                    >
                      <Layers size={11} />
                      <span>{isExpanded ? 'Hide Payload' : 'View Payload'}</span>
                      {isExpanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                    </button>
                  )}
                </div>

                {/* Collapsible Arguments Payload */}
                {isExpanded && hasArgs && (
                  <div className="pt-2 border-t border-[#262C24] space-y-1">
                    <div className="text-[10px] font-mono uppercase tracking-wider text-[#6F736A]">
                      Intercepted Tool Arguments
                    </div>
                    <pre className="bg-[#141713] border border-[#262C24] rounded-lg p-3 text-[11px] font-mono text-[#D0DEC7] overflow-x-auto leading-relaxed">
                      {JSON.stringify(e.arguments, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          );
        })}

        {filteredEvents.length === 0 && (
          <div className="pl-6 md:pl-8 py-16 text-center text-[#6F736A] text-xs font-mono">
            {events.length === 0
              ? 'No audit events recorded in audit.db.'
              : 'No audit records match the active search or decision filter.'}
          </div>
        )}
      </div>
    </div>
  );
};
