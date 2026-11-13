import React, { useEffect, useState } from 'react';
import { getApprovals, approveRequest, rejectRequest } from '../services/api';
import { CheckCircle2, Clock, AlertCircle, RefreshCw, Shield } from 'lucide-react';
import type { ApprovalRequest } from '../types';

export const Approvals: React.FC = () => {
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [processingId, setProcessingId] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<{ id: string; text: string; type: 'success' | 'error' } | null>(null);

  const reloadApprovals = () => {
    setRefreshing(true);
    getApprovals()
      .then(data => {
        setApprovals(data);
        setError(null);
      })
      .catch(err => {
        setError(err.message || "Failed to load approvals.");
      })
      .finally(() => {
        setLoading(false);
        setRefreshing(false);
      });
  };

  useEffect(() => {
    let isMounted = true;
    getApprovals()
      .then(data => {
        if (isMounted) {
          setApprovals(data);
          setLoading(false);
        }
      })
      .catch(err => {
        if (isMounted) {
          setError(err.message || "Failed to load approvals.");
          setLoading(false);
        }
      });
    return () => {
      isMounted = false;
    };
  }, []);

  const handleApprove = async (id: string) => {
    setProcessingId(id);
    setActionMessage(null);
    try {
      await approveRequest(id);
      setActionMessage({ id, text: "Request approved and authorized for execution.", type: "success" });
      reloadApprovals();
    } catch (err: any) {
      setActionMessage({ id, text: err.response?.data?.detail || err.message, type: "error" });
    } finally {
      setProcessingId(null);
    }
  };

  const handleReject = async (id: string) => {
    if (window.confirm("Reject this agent tool request? The action will remain blocked.")) {
      setProcessingId(id);
      setActionMessage(null);
      try {
        await rejectRequest(id);
        setActionMessage({ id, text: "Request rejected. Tool execution remains blocked.", type: "success" });
        reloadApprovals();
      } catch (err: any) {
        setActionMessage({ id, text: err.response?.data?.detail || err.message, type: "error" });
      } finally {
        setProcessingId(null);
      }
    }
  };

  const getRiskLevel = (op: string) => {
    if (op === "send_email" || op === "delete_record") return { level: "HIGH", color: "text-[#C25D54]" };
    if (op === "create_record" || op === "create_calendar_event") return { level: "MEDIUM", color: "text-[#D4A359]" };
    return { level: "LOW", color: "text-[#8FA887]" };
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-80 space-y-3">
        <div className="w-6 h-6 border-2 border-[#A2B89A] border-t-transparent rounded-full animate-spin" />
        <p className="text-[#A5A69C] font-mono text-xs uppercase tracking-wider">
          Querying approval database (approval.db)...
        </p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-4xl mx-auto bg-[#C25D54]/10 border border-[#C25D54]/30 rounded-xl p-5 text-[#C25D54] space-y-2">
        <div className="flex items-center gap-2 font-bold text-sm">
          <AlertCircle size={18} /> Error fetching approvals
        </div>
        <p className="text-xs text-[#A5A69C]">{error}</p>
      </div>
    );
  }

  const pendingApprovals = approvals.filter(a => a.status === 'PENDING');
  const resolvedApprovals = approvals.filter(a => a.status !== 'PENDING');

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between sm:items-end gap-4 border-b border-[#262C24] pb-5">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-[9.5px] font-mono tracking-[0.22em] text-[#A2B89A] uppercase font-medium">
              HUMAN-IN-THE-LOOP ARBITRATION
            </span>
            <span className="text-[#6F736A] text-xs font-mono">SQLite (approval.db)</span>
          </div>
          <h1 className="font-serif text-2xl lg:text-3xl font-normal text-[#F0EEE5] tracking-tight">Human Authorization Center</h1>
          <p className="text-[#A5A69C] text-xs mt-1 max-w-xl">
            State-machine gate for state-changing agent actions. Every pending request is cryptographically bound to the SHA-256 hash of its exact tool arguments.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={reloadApprovals}
            disabled={refreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#141713] hover:bg-[#191C18] text-[#A5A69C] hover:text-[#F0EEE5] text-xs font-mono rounded-lg border border-[#262C24] transition-colors disabled:opacity-50"
          >
            <RefreshCw size={12} className={refreshing ? 'animate-spin text-[#A2B89A]' : 'text-[#A2B89A]'} />
            <span>{refreshing ? 'Refreshing...' : 'Refresh'}</span>
          </button>
          <div className="px-3 py-1.5 rounded-lg bg-[#141713] border border-[#262C24] text-xs font-mono">
            <span className="text-[#D4A359] font-bold">{pendingApprovals.length} Pending</span>
            <span className="text-[#6F736A] mx-1.5">/</span>
            <span className="text-[#A5A69C]">{approvals.length} Total</span>
          </div>
        </div>
      </div>

      {/* Action status notification */}
      {actionMessage && (
        <div className={`p-3.5 rounded-xl text-xs font-mono flex items-center justify-between border ${
          actionMessage.type === 'success' 
            ? 'bg-[#8FA887]/10 text-[#8FA887] border-[#8FA887]/30' 
            : 'bg-[#C25D54]/10 text-[#C25D54] border-[#C25D54]/30'
        }`}>
          <span>{actionMessage.text}</span>
          <button onClick={() => setActionMessage(null)} className="text-current hover:opacity-75 font-semibold">
            Dismiss
          </button>
        </div>
      )}

      {/* Pending Authorizations Section */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <Clock size={14} className="text-[#D4A359]" />
          <h2 className="text-xs font-mono uppercase tracking-widest text-[#F0EEE5] font-semibold">
            Pending Authorizations ({pendingApprovals.length})
          </h2>
        </div>

        {pendingApprovals.length === 0 ? (
          <div className="p-8 text-center bg-[#141713] border border-[#262C24] rounded-xl space-y-2">
            <CheckCircle2 size={24} className="mx-auto text-[#8FA887] mb-1" />
            <div className="text-[#F0EEE5] font-medium text-xs">No Pending Approval Requests</div>
            <p className="text-[11px] text-[#A5A69C] max-w-sm mx-auto">
              All state-changing agent actions have been arbitrated. Incoming mutating tool calls will hold here awaiting explicit authorization.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {pendingApprovals.map(a => {
              const risk = getRiskLevel(a.operation);
              const isBusy = processingId === a.approval_id;

              return (
                <div 
                  key={a.approval_id} 
                  className="bg-[#191C18] border border-[#262C24] hover:border-[#343B32] rounded-xl overflow-hidden flex flex-col justify-between transition-colors shadow-xs"
                >
                  <div className="p-3.5 border-b border-[#262C24] bg-[#141713]/80 flex justify-between items-center">
                    <div className="flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#D4A359] animate-pulse" />
                      <span className="text-[11px] font-bold font-mono text-[#D4A359]">
                        PENDING AUTHORIZATION
                      </span>
                    </div>
                    <span className="text-[10px] text-[#6F736A] font-mono">
                      {new Date(a.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  
                  <div className="p-4 flex-1 space-y-3 text-xs">
                    <div>
                      <div className="text-[10px] text-[#6F736A] uppercase tracking-wider font-semibold font-mono mb-1">
                        Requested Operation
                      </div>
                      <div className="font-mono text-[#F0EEE5] bg-[#141713] rounded-lg p-2.5 font-bold border border-[#262C24] truncate">
                        {a.operation}
                      </div>
                    </div>
                    
                    <div className="grid grid-cols-2 gap-2 font-mono text-[11px]">
                      <div>
                        <div className="text-[10px] text-[#6F736A] uppercase tracking-wider font-semibold mb-0.5">Calling Agent</div>
                        <div className="text-[#A5A69C] truncate">{a.agent_id}</div>
                      </div>
                      <div>
                        <div className="text-[10px] text-[#6F736A] uppercase tracking-wider font-semibold mb-0.5">Risk Tier</div>
                        <div className={`font-bold ${risk.color}`}>{risk.level} RISK</div>
                      </div>
                    </div>

                    <div>
                      <div className="text-[10px] text-[#6F736A] uppercase tracking-wider font-semibold font-mono mb-0.5">
                        Payload Hash Binding (SHA-256)
                      </div>
                      <div className="text-[10px] text-[#A5A69C] font-mono truncate bg-[#141713] px-2.5 py-1.5 rounded-lg border border-[#262C24]" title={a.request_hash}>
                        {a.request_hash}
                      </div>
                    </div>

                    <div className="pt-2 border-t border-[#262C24] flex items-center justify-between text-[10px] font-mono text-[#6F736A]">
                      <span className="truncate max-w-[160px]" title={a.approval_id}>ID: {a.approval_id}</span>
                      <span className="text-[#D4A359]">Awaiting decision</span>
                    </div>
                  </div>

                  <div className="p-3 bg-[#141713] border-t border-[#262C24] flex gap-2">
                    <button 
                      disabled={isBusy}
                      onClick={() => handleReject(a.approval_id)}
                      className="flex-1 py-1.5 rounded-lg bg-[#C25D54]/10 hover:bg-[#C25D54]/20 text-[#C25D54] border border-[#C25D54]/30 transition-colors text-xs font-mono font-medium disabled:opacity-50"
                    >
                      {isBusy ? 'Processing...' : 'Reject Action'}
                    </button>
                    <button 
                      disabled={isBusy}
                      onClick={() => handleApprove(a.approval_id)}
                      className="flex-1 py-1.5 rounded-lg bg-[#8FA887]/15 hover:bg-[#8FA887]/25 text-[#8FA887] border border-[#8FA887]/30 transition-colors text-xs font-mono font-bold disabled:opacity-50"
                    >
                      {isBusy ? 'Processing...' : 'Approve Execution'}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Historical Resolved Authorizations Table (Clean rows, no nested cards) */}
      {resolvedApprovals.length > 0 && (
        <div className="space-y-3 pt-4 border-t border-[#262C24]">
          <div className="flex items-center gap-2">
            <Shield size={14} className="text-[#6F736A]" />
            <h2 className="text-xs font-mono uppercase tracking-widest text-[#A5A69C] font-semibold">
              Historical Approvals &amp; Audit ({resolvedApprovals.length})
            </h2>
          </div>

          <div className="bg-[#191C18] border border-[#262C24] rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#141713] text-[#6F736A] uppercase tracking-wider text-[10px] border-b border-[#262C24]">
                  <tr>
                    <th className="py-2.5 px-3.5">Time</th>
                    <th className="py-2.5 px-3.5">Operation</th>
                    <th className="py-2.5 px-3.5">Agent</th>
                    <th className="py-2.5 px-3.5">Hash Binding</th>
                    <th className="py-2.5 px-3.5 text-right">Verdict</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#262C24]">
                  {resolvedApprovals.map(a => {
                    const isApproved = a.status === 'APPROVED';
                    return (
                      <tr key={a.approval_id} className="hover:bg-[#141713]/60 transition-colors">
                        <td className="py-2.5 px-3.5 text-[#6F736A] whitespace-nowrap text-[11px]">
                          {new Date(a.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="py-2.5 px-3.5 font-bold text-[#F0EEE5]">
                          {a.operation}
                        </td>
                        <td className="py-2.5 px-3.5 text-[#A5A69C] text-[11px]">
                          {a.agent_id}
                        </td>
                        <td className="py-2.5 px-3.5 text-[#6F736A] text-[10px] truncate max-w-xs font-mono" title={a.request_hash}>
                          {a.request_hash}
                        </td>
                        <td className="py-2.5 px-3.5 text-right whitespace-nowrap">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                            isApproved
                              ? 'bg-[#8FA887]/10 text-[#8FA887] border-[#8FA887]/25'
                              : 'bg-[#C25D54]/10 text-[#C25D54] border-[#C25D54]/25'
                          }`}>
                            {a.status}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
