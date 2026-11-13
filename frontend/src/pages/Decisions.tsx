import React, { useEffect, useState } from 'react';
import { getDecisions } from '../services/api';
import { Search, Filter, AlertCircle, X } from 'lucide-react';
import type { SecurityDecision } from '../types';

export const Decisions: React.FC = () => {
  const [decisions, setDecisions] = useState<SecurityDecision[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedReq, setSelectedReq] = useState<SecurityDecision | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [decisionFilter, setDecisionFilter] = useState<string>("ALL");

  useEffect(() => {
    let isMounted = true;
    getDecisions()
      .then(data => {
        if (isMounted) {
          setDecisions(data);
          setLoading(false);
        }
      })
      .catch(err => {
        if (isMounted) {
          setError(err.message || "Failed to load security decisions.");
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, []);

  const getBadge = (decision: string) => {
    switch (decision) {
      case 'ALLOW': 
        return <span className="px-2 py-0.5 bg-[#8FA887]/10 text-[#8FA887] border border-[#8FA887]/25 rounded text-[10px] font-bold font-mono">ALLOW</span>;
      case 'BLOCK': 
        return <span className="px-2 py-0.5 bg-[#C25D54]/10 text-[#C25D54] border border-[#C25D54]/25 rounded text-[10px] font-bold font-mono">BLOCK</span>;
      case 'REQUIRE_APPROVAL': 
        return <span className="px-2 py-0.5 bg-[#D4A359]/10 text-[#D4A359] border border-[#D4A359]/25 rounded text-[10px] font-bold font-mono">APPROVAL</span>;
      default: 
        return <span className="px-2 py-0.5 bg-[#141713] text-[#6F736A] border border-[#262C24] rounded text-[10px] font-bold font-mono">{decision}</span>;
    }
  };

  const filteredDecisions = decisions.filter(d => {
    const matchesSearch = 
      (d.operation || "").toLowerCase().includes(searchQuery.toLowerCase()) ||
      (d.agent_id || "").toLowerCase().includes(searchQuery.toLowerCase()) ||
      (d.event_id || "").toLowerCase().includes(searchQuery.toLowerCase()) ||
      (d.replay?.request_id || "").toLowerCase().includes(searchQuery.toLowerCase());

    const matchesFilter = decisionFilter === "ALL" || d.final_decision === decisionFilter;
    return matchesSearch && matchesFilter;
  });

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-80 space-y-3">
        <div className="w-6 h-6 border-2 border-[#A2B89A] border-t-transparent rounded-full animate-spin" />
        <p className="text-[#A5A69C] font-mono text-xs uppercase tracking-wider">Loading security decisions...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-4xl mx-auto bg-[#C25D54]/10 border border-[#C25D54]/30 rounded-xl p-5 text-[#C25D54] space-y-2">
        <div className="flex items-center gap-2 font-bold text-sm">
          <AlertCircle size={18} /> Error fetching decisions
        </div>
        <p className="text-xs text-[#A5A69C]">{error}</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="border-b border-[#262C24] pb-3">
        <div className="text-[9.5px] font-mono uppercase tracking-[0.22em] text-[#A2B89A] font-medium leading-none mb-1.5">
          RUNTIME INTERCEPTION
        </div>
        <h1 className="font-serif text-2xl lg:text-3xl font-normal text-[#F0EEE5] tracking-tight">
          Security Decisions
        </h1>
        <p className="text-[#A5A69C] text-xs mt-1">
          Real-time interception decisions across all 8 security validation boundaries.
        </p>
      </div>

      <div className="flex flex-col lg:flex-row h-full lg:h-[calc(100vh-160px)] gap-5">
      {/* Table Side */}
      <div className={`flex flex-col bg-[#191C18] border border-[#262C24] rounded-xl overflow-hidden transition-all duration-300 ${selectedReq ? 'lg:w-7/12' : 'w-full'}`}>
        {/* Search & Filter Controls */}
        <div className="p-3 border-b border-[#262C24] flex flex-col sm:flex-row justify-between items-stretch sm:items-center bg-[#141713]/80 gap-2.5">
          <div className="relative flex-1">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#6F736A]" />
            <input 
              type="text" 
              placeholder="Search operation, agent ID, request hash..." 
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 bg-[#101210] border border-[#262C24] rounded-lg text-xs focus:outline-none focus:border-[#A2B89A] transition-colors w-full text-[#F0EEE5] placeholder-[#6F736A] font-mono" 
            />
          </div>
          <div className="flex items-center gap-1.5 bg-[#101210] border border-[#262C24] rounded-lg px-2.5 py-1">
            <Filter size={11} className="text-[#6F736A]" />
            <select
              value={decisionFilter}
              onChange={(e) => setDecisionFilter(e.target.value)}
              className="bg-transparent text-[#F0EEE5] text-xs font-mono focus:outline-none cursor-pointer"
            >
              <option value="ALL" className="bg-[#191C18]">All Decisions ({decisions.length})</option>
              <option value="ALLOW" className="bg-[#191C18] text-[#8FA887]">ALLOW</option>
              <option value="BLOCK" className="bg-[#191C18] text-[#C25D54]">BLOCK</option>
              <option value="REQUIRE_APPROVAL" className="bg-[#191C18] text-[#D4A359]">REQUIRE_APPROVAL</option>
            </select>
          </div>
        </div>
        
        {/* Decisions Table */}
        <div className="overflow-y-auto flex-1">
          <table className="w-full text-left text-xs font-sans">
            <thead className="bg-[#141713] text-[#6F736A] sticky top-0 backdrop-blur-md text-[10px] font-mono uppercase tracking-wider border-b border-[#262C24]">
              <tr>
                <th className="py-2.5 px-3.5 font-medium">Time</th>
                <th className="py-2.5 px-3.5 font-medium">Operation</th>
                <th className="py-2.5 px-3.5 font-medium hidden lg:table-cell">Agent</th>
                <th className="py-2.5 px-3.5 font-medium hidden xl:table-cell">Trust</th>
                <th className="py-2.5 px-3.5 font-medium text-right">Verdict</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#262C24]">
              {filteredDecisions.map(d => {
                const isSelected = selectedReq?.event_id === d.event_id;
                return (
                  <tr 
                    key={d.event_id} 
                    onClick={() => setSelectedReq(d)}
                    className={`hover:bg-[#141713]/60 cursor-pointer transition-colors ${
                      isSelected ? 'bg-[#141713] border-l-2 border-[#A2B89A]' : 'border-l-2 border-transparent'
                    }`}
                  >
                    <td className="py-2.5 px-3.5 text-[#6F736A] font-mono text-[11px] whitespace-nowrap">
                      {new Date(d.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-3.5 font-bold font-mono text-[#F0EEE5]">
                      {d.operation}
                    </td>
                    <td className="py-2.5 px-3.5 text-[#A5A69C] hidden lg:table-cell font-mono text-[11px]">
                      {d.agent_id}
                    </td>
                    <td className="py-2.5 px-3.5 text-[#A5A69C] hidden xl:table-cell font-mono text-[11px]">
                      {d.destination?.trust || "—"}
                    </td>
                    <td className="py-2.5 px-3.5 text-right whitespace-nowrap">
                      {getBadge(d.final_decision)}
                    </td>
                  </tr>
                );
              })}
              {filteredDecisions.length === 0 && (
                <tr>
                  <td colSpan={5} className="py-12 text-center text-[#6F736A] text-xs font-mono">
                    {decisions.length === 0 ? "No security events recorded in audit.db." : "No events match active filter."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Details Side / Inspection Drawer */}
      {selectedReq && (
        <div className="lg:w-5/12 bg-[#191C18] border border-[#262C24] rounded-xl flex flex-col overflow-hidden animate-in slide-in-from-right-2 duration-150">
          <div className="p-3.5 border-b border-[#262C24] flex justify-between items-start bg-[#141713]/80">
            <div>
              <div className="flex items-center gap-2 mb-0.5">
                <span className="text-[10px] font-mono uppercase tracking-wider text-[#A2B89A] font-semibold">
                  INTERCEPTION INSPECTOR
                </span>
                <span className="text-[#6F736A] text-xs font-mono">•</span>
                <span className="text-[#6F736A] text-[11px] font-mono">{new Date(selectedReq.timestamp).toLocaleTimeString()}</span>
              </div>
              <h2 className="text-sm font-bold font-mono text-[#F0EEE5]">{selectedReq.operation}</h2>
              <div className="text-[10px] text-[#6F736A] font-mono mt-0.5 truncate max-w-xs" title={selectedReq.event_id}>
                ID: {selectedReq.event_id}
              </div>
            </div>
            <div className="flex items-center gap-2">
              {getBadge(selectedReq.final_decision)}
              <button 
                onClick={() => setSelectedReq(null)}
                className="p-1 rounded text-[#6F736A] hover:text-[#F0EEE5] hover:bg-[#141713] transition-colors"
                aria-label="Close details"
              >
                <X size={15} />
              </button>
            </div>
          </div>
          
          <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs font-sans">
            {/* Enforcement Outcome Summary */}
            <div className="bg-[#141713] rounded-lg p-3 border border-[#262C24] space-y-1.5 font-mono text-xs">
              <div className="flex justify-between py-0.5">
                <span className="text-[#6F736A]">Decision:</span>
                <span className="font-bold text-[#F0EEE5]">{selectedReq.final_decision}</span>
              </div>
              <div className="flex justify-between py-0.5 border-t border-[#262C24]">
                <span className="text-[#6F736A]">Reason:</span>
                <span className="text-[#F0EEE5] truncate max-w-xs" title={selectedReq.reason}>{selectedReq.reason}</span>
              </div>
              <div className="flex justify-between py-0.5 border-t border-[#262C24]">
                <span className="text-[#6F736A]">Downstream:</span>
                <span className={
                  selectedReq.downstream_executed ? "text-[#8FA887] font-bold" :
                  selectedReq.final_decision === 'REQUIRE_APPROVAL' ? "text-[#D4A359] font-bold" :
                  "text-[#C25D54] font-bold"
                }>
                  {selectedReq.downstream_executed ? "EXECUTED" :
                   selectedReq.final_decision === 'REQUIRE_APPROVAL' ? "PENDING APPROVAL" :
                   "BLOCKED BY GATEWAY"}
                </span>
              </div>
              {selectedReq.replay?.request_id && (
                <div className="flex justify-between py-0.5 border-t border-[#262C24]">
                  <span className="text-[#6F736A]">Replay Nonce:</span>
                  <span className="text-[#A5A69C] truncate max-w-[150px]">{selectedReq.replay.request_id}</span>
                </div>
              )}
            </div>

            {/* Layer-by-Layer Verification Matrix */}
            <div className="space-y-2">
              <div className="text-[10px] font-mono uppercase tracking-wider text-[#6F736A] font-semibold">
                Layer Verification Outcomes
              </div>
              <div className="grid grid-cols-2 gap-2">
                <LayerCard label="1. Provenance" val={selectedReq.provenance?.verification} />
                <LayerCard label="2. Replay" val={selectedReq.replay?.decision} />
                <LayerCard label="3. Capability" val={selectedReq.capability?.decision} />
                <LayerCard label="4. Destination" val={selectedReq.destination?.trust} />
                <LayerCard label="5. Risk Tier" val={selectedReq.risk?.level} />
                <LayerCard label="6. Context" val={selectedReq.context?.decision} />
                <LayerCard label="7. Approval" val={selectedReq.approval?.status} />
              </div>
            </div>

            {/* Payload Arguments if available */}
            {selectedReq.arguments && Object.keys(selectedReq.arguments).length > 0 && (
              <div className="space-y-1.5">
                <div className="text-[10px] font-mono uppercase tracking-wider text-[#6F736A] font-semibold">
                  Payload Arguments (Untrusted)
                </div>
                <pre className="bg-[#101210] border border-[#262C24] rounded-lg p-3 font-mono text-[11px] text-[#D0DEC7] overflow-x-auto whitespace-pre-wrap break-words max-h-40">
                  {JSON.stringify(selectedReq.arguments, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
      </div>
    </div>
  );
};

interface LayerCardProps {
  label: string;
  val?: string | null;
}

const LayerCard: React.FC<LayerCardProps> = ({ label, val }) => (
  <div className="bg-[#141713] border border-[#262C24] rounded-lg p-2">
    <div className="text-[9px] text-[#6F736A] uppercase tracking-wider mb-0.5 font-semibold font-mono">{label}</div>
    <div className={`font-mono text-xs font-bold ${
      !val || val === 'SKIPPED' || val === 'NOT_EVALUATED' ? 'text-[#6F736A]' :
      val === 'VALID' || val === 'ALLOW' || val === 'CONTROLLED' || val === 'LOW' || val === 'MEDIUM' ? 'text-[#8FA887]' :
      val === 'REQUIRE_APPROVAL' || val === 'PENDING' ? 'text-[#D4A359]' :
      'text-[#C25D54]'
    }`}>
      {val || "NOT_EVALUATED"}
    </div>
  </div>
);
