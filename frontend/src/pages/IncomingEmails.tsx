import React, { useEffect, useState, useCallback } from 'react';
import {
  getEmailSummary,
  getEmails,
  getEmailDetail,
} from '../services/api';
import type {
  EmailSummary,
  EmailRecord,
  EmailFilterParams,
} from '../types';
import {
  Mail,
  Shield,
  AlertTriangle,
  AlertCircle,
  CheckCircle2,
  Clock,
  Search,
  Filter,
  RefreshCw,
  X,
  Eye,
  User,
  Calendar,
  ChevronLeft,
  ChevronRight,
  Info,
  Hash,
  FileText,
  Lock,
} from 'lucide-react';

export const IncomingEmails: React.FC = () => {
  const [summary, setSummary] = useState<EmailSummary | null>(null);
  const [emails, setEmails] = useState<EmailRecord[]>([]);
  const [totalItems, setTotalItems] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(15);

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [classificationFilter, setClassificationFilter] = useState<string>('ALL');
  const [riskFilter, setRiskFilter] = useState<string>('ALL');
  const [stateFilter, setStateFilter] = useState<string>('ALL');
  const [reviewFilter, setReviewFilter] = useState<string>('ALL');

  // Detail selection
  const [selectedEmail, setSelectedEmail] = useState<EmailRecord | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  const fetchData = useCallback(() => {
    const params: EmailFilterParams = {
      page,
      page_size: pageSize,
    };

    if (classificationFilter !== 'ALL') params.classification = classificationFilter;
    if (riskFilter !== 'ALL') params.risk_level = riskFilter;
    if (stateFilter !== 'ALL') params.state = stateFilter;
    if (reviewFilter === 'REVIEW_REQUIRED') params.requires_human_review = true;
    if (reviewFilter === 'NO_REVIEW') params.requires_human_review = false;
    if (searchQuery.trim()) params.search = searchQuery.trim();

    Promise.all([getEmailSummary(), getEmails(params)])
      .then(([summaryData, listData]) => {
        setSummary(summaryData);
        setEmails(listData.items);
        setTotalItems(listData.total);
        setTotalPages(listData.total_pages || 1);
        setError(null);
      })
      .catch((err: any) => {
        setError(err?.response?.data?.detail || err?.message || 'Failed to fetch incoming email data.');
      })
      .finally(() => {
        setLoading(false);
        setRefreshing(false);
      });
  }, [page, pageSize, classificationFilter, riskFilter, stateFilter, reviewFilter, searchQuery]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleSelectEmail = async (email: EmailRecord) => {
    setSelectedEmail(email);
    setLoadingDetail(true);
    try {
      const detail = await getEmailDetail(email.message_id);
      setSelectedEmail(detail);
    } catch {
      // Fallback to table row data if detail fetch fails
    } finally {
      setLoadingDetail(false);
    }
  };

  const getClassificationBadge = (classification?: string | null) => {
    switch (classification) {
      case 'SAFE':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 bg-[#8FA887]/10 text-[#8FA887] border border-[#8FA887]/25 rounded text-[11px] font-bold font-mono tracking-wide">
            <CheckCircle2 size={12} className="shrink-0" />
            SAFE
          </span>
        );
      case 'SUSPICIOUS':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 bg-[#C25D54]/10 text-[#C25D54] border border-[#C25D54]/25 rounded text-[11px] font-bold font-mono tracking-wide">
            <AlertTriangle size={12} className="shrink-0" />
            SUSPICIOUS
          </span>
        );
      case 'NEEDS_REVIEW':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 bg-[#D4A359]/10 text-[#D4A359] border border-[#D4A359]/25 rounded text-[11px] font-bold font-mono tracking-wide">
            <AlertCircle size={12} className="shrink-0" />
            NEEDS_REVIEW
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 bg-[#141713] text-[#6F736A] border border-[#262C24] rounded text-[11px] font-mono">
            <Clock size={12} className="shrink-0" />
            UNCLASSIFIED
          </span>
        );
    }
  };

  const getRiskBadge = (risk?: string | null) => {
    switch (risk) {
      case 'LOW':
        return <span className="px-2 py-0.5 bg-[#8FA887]/10 text-[#8FA887] border border-[#8FA887]/25 rounded text-[10px] font-bold font-mono">LOW RISK</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 bg-[#D4A359]/10 text-[#D4A359] border border-[#D4A359]/25 rounded text-[10px] font-bold font-mono">MEDIUM RISK</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 bg-[#C25D54]/10 text-[#C25D54] border border-[#C25D54]/25 rounded text-[10px] font-bold font-mono">HIGH RISK</span>;
      default:
        return <span className="px-2 py-0.5 bg-[#141713] text-[#6F736A] border border-[#262C24] rounded text-[10px] font-mono">UNRATED</span>;
    }
  };

  const getStateBadge = (state: string) => {
    switch (state) {
      case 'PROCESSED':
        return <span className="px-2 py-0.5 bg-[#8FA887]/10 text-[#8FA887] border border-[#8FA887]/25 rounded text-[10px] font-mono font-bold">PROCESSED</span>;
      case 'PROCESSING':
        return <span className="px-2 py-0.5 bg-[#D0DEC7]/10 text-[#D0DEC7] border border-[#D0DEC7]/25 rounded text-[10px] font-mono font-bold animate-pulse">PROCESSING</span>;
      case 'DISCOVERED':
        return <span className="px-2 py-0.5 bg-[#141713] text-[#A5A69C] border border-[#262C24] rounded text-[10px] font-mono font-bold">DISCOVERED</span>;
      case 'FAILED':
        return <span className="px-2 py-0.5 bg-[#C25D54]/10 text-[#C25D54] border border-[#C25D54]/25 rounded text-[10px] font-mono font-bold">FAILED</span>;
      default:
        return <span className="px-2 py-0.5 bg-[#141713] text-[#6F736A] rounded text-[10px] font-mono">{state}</span>;
    }
  };

  if (loading && !summary) {
    return (
      <div className="flex flex-col items-center justify-center h-80 space-y-4">
        <div className="w-7 h-7 border-2 border-[#A2B89A] border-t-transparent rounded-full animate-spin"></div>
        <p className="text-[#A5A69C] font-mono text-xs tracking-wider animate-pulse uppercase">
          Loading incoming email security records (email_watcher.db)...
        </p>
      </div>
    );
  }

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
  };

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-[#262C24] pb-5">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-[9.5px] font-mono tracking-[0.22em] text-[#A2B89A] uppercase font-medium">
              INCOMING EMAIL PERIMETER (PHASE 1 &amp; 2)
            </span>
            <span className="text-[#6F736A] text-xs font-mono">SQLite (email_watcher.db)</span>
          </div>
          <h1 className="font-serif text-2xl lg:text-3xl font-normal text-[#F0EEE5] tracking-tight flex items-center gap-2.5">
            <Mail className="text-[#A2B89A]" size={24} /> Incoming Emails Review
          </h1>
          <p className="text-[#A5A69C] text-xs mt-1">
            Autonomous Gmail watcher, natural-language AI summaries, and local LLM security risk classification.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="flex items-center gap-2 px-3 py-1.5 bg-[#141713] hover:bg-[#191C18] text-[#F0EEE5] text-xs font-mono rounded-lg border border-[#262C24] hover:border-[#343B32] transition-colors disabled:opacity-50"
          >
            <RefreshCw size={13} className={refreshing ? 'animate-spin text-[#A2B89A]' : 'text-[#A2B89A]'} />
            <span>{refreshing ? 'Refreshing...' : 'Refresh'}</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-[#C25D54]/10 border border-[#C25D54]/30 rounded-xl p-4 text-[#C25D54] space-y-1 text-xs flex items-start gap-3">
          <AlertCircle size={17} className="shrink-0 mt-0.5" />
          <div>
            <div className="font-bold">Error loading incoming email data</div>
            <div className="text-[#A5A69C] text-[11px]">{error}</div>
          </div>
        </div>
      )}

      {/* Summary KPI Cards */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          {/* Total Discovered */}
          <div className="bg-[#191C18] border border-[#262C24] hover:border-[#343B32] rounded-xl p-3.5 transition-colors">
            <div className="text-[10px] font-mono text-[#6F736A] uppercase tracking-wider mb-1 flex items-center justify-between">
              Discovered
              <Mail size={13} className="text-[#A2B89A]" />
            </div>
            <div className="text-2xl font-bold font-mono text-[#F0EEE5]">{summary.total_discovered}</div>
            <div className="text-[10px] text-[#A5A69C] mt-1 font-mono">Total in SQLite watcher</div>
          </div>

          {/* Classified */}
          <div className="bg-[#191C18] border border-[#262C24] hover:border-[#343B32] rounded-xl p-3.5 transition-colors">
            <div className="text-[10px] font-mono text-[#6F736A] uppercase tracking-wider mb-1 flex items-center justify-between">
              Classified
              <CheckCircle2 size={13} className="text-[#8FA887]" />
            </div>
            <div className="text-2xl font-bold font-mono text-[#8FA887]">{summary.classified_count}</div>
            <div className="text-[10px] text-[#A5A69C] mt-1 font-mono">Processed by AI agent</div>
          </div>

          {/* Suspicious */}
          <div className="bg-[#191C18] border border-[#262C24] hover:border-[#343B32] rounded-xl p-3.5 transition-colors">
            <div className="text-[10px] font-mono text-[#6F736A] uppercase tracking-wider mb-1 flex items-center justify-between">
              Suspicious
              <AlertTriangle size={13} className="text-[#C25D54]" />
            </div>
            <div className="text-2xl font-bold font-mono text-[#C25D54]">
              {summary.by_classification.SUSPICIOUS || 0}
            </div>
            <div className="text-[10px] text-[#C25D54] mt-1 font-mono font-semibold">Flagged security risks</div>
          </div>

          {/* Needs Review */}
          <div className="bg-[#191C18] border border-[#262C24] hover:border-[#343B32] rounded-xl p-3.5 transition-colors">
            <div className="text-[10px] font-mono text-[#6F736A] uppercase tracking-wider mb-1 flex items-center justify-between">
              Needs Review
              <AlertCircle size={13} className="text-[#D4A359]" />
            </div>
            <div className="text-2xl font-bold font-mono text-[#D4A359]">
              {summary.by_classification.NEEDS_REVIEW || 0}
            </div>
            <div className="text-[10px] text-[#A5A69C] mt-1 font-mono">Ambiguous or failures</div>
          </div>

          {/* Review Required Total */}
          <div className="bg-[#191C18] border border-[#262C24] hover:border-[#343B32] rounded-xl p-3.5 transition-colors">
            <div className="text-[10px] font-mono text-[#6F736A] uppercase tracking-wider mb-1 flex items-center justify-between">
              Human Review
              <Eye size={13} className="text-[#D0DEC7]" />
            </div>
            <div className="text-2xl font-bold font-mono text-[#D0DEC7]">
              {summary.requires_human_review_count}
            </div>
            <div className="text-[10px] text-[#A5A69C] mt-1 font-mono">Mandatory check enforced</div>
          </div>

          {/* Unprocessed / Pending */}
          <div className="bg-[#191C18] border border-[#262C24] hover:border-[#343B32] rounded-xl p-3.5 transition-colors">
            <div className="text-[10px] font-mono text-[#6F736A] uppercase tracking-wider mb-1 flex items-center justify-between">
              Unprocessed
              <Clock size={13} className="text-[#6F736A]" />
            </div>
            <div className="text-2xl font-bold font-mono text-[#A5A69C]">
              {summary.unprocessed_count}
            </div>
            <div className="text-[10px] text-[#D4A359] mt-1 font-mono font-semibold">NOT treated as safe</div>
          </div>
        </div>
      )}

      {/* Untrusted Email Security Callout */}
      <div className="bg-[#141713] border border-[#262C24] rounded-xl p-3.5 flex items-start gap-3">
        <Shield size={17} className="text-[#A2B89A] shrink-0 mt-0.5" />
        <div className="text-xs text-[#A5A69C] space-y-1">
          <div className="font-semibold text-[#F0EEE5] flex items-center gap-2">
            <span>Security Isolation &amp; Advisory Boundary</span>
            <span className="text-[10px] font-mono px-1.5 py-0.2 bg-[#101210] border border-[#262C24] text-[#8FA887] rounded">
              FAIL-CLOSED
            </span>
          </div>
          <p className="leading-relaxed text-[11px]">
            All incoming email subjects, senders, and content are strictly untrusted external inputs. Classifications and summaries are informational
            assessments produced by local Ollama (<code className="text-[#D0DEC7]">qwen3:8b</code>) and do NOT grant authorization.
            Emails marked <span className="text-[#8FA887] font-bold">SAFE</span> are not exempt from runtime gateway policy,
            and unprocessed emails are never treated as safe.
          </p>
        </div>
      </div>

      {/* Main Workspace (Table + Inspection Detail) */}
      <div className="flex flex-col lg:flex-row gap-5">
        {/* Table View */}
        <div className={`bg-[#191C18] border border-[#262C24] rounded-xl flex flex-col overflow-hidden transition-all duration-300 ${selectedEmail ? 'lg:w-7/12' : 'w-full'}`}>
          {/* Search and Filters Bar */}
          <div className="p-3.5 border-b border-[#262C24] bg-[#141713]/60 space-y-2.5">
            <div className="flex flex-col sm:flex-row gap-2.5">
              {/* Search */}
              <div className="relative flex-1">
                <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#6F736A]" />
                <input
                  type="text"
                  placeholder="Search subject, sender, or snippet..."
                  value={searchQuery}
                  onChange={(e) => {
                    setSearchQuery(e.target.value);
                    setPage(1);
                  }}
                  className="pl-8 pr-3 py-1.5 bg-[#141713] border border-[#262C24] rounded-lg text-xs focus:outline-none focus:border-[#A2B89A] transition-colors w-full text-[#F0EEE5] placeholder-[#6F736A] font-mono"
                />
              </div>

              {/* Classification Filter */}
              <div className="flex items-center gap-1.5 bg-[#141713] border border-[#262C24] rounded-lg px-2 py-1">
                <Filter size={11} className="text-[#6F736A] shrink-0" />
                <select
                  value={classificationFilter}
                  onChange={(e) => {
                    setClassificationFilter(e.target.value);
                    setPage(1);
                  }}
                  className="bg-transparent text-[#F0EEE5] text-xs font-mono focus:outline-none cursor-pointer"
                >
                  <option value="ALL" className="bg-[#191C18] text-[#F0EEE5]">All Classifications</option>
                  <option value="SAFE" className="bg-[#191C18] text-[#8FA887]">SAFE Only</option>
                  <option value="SUSPICIOUS" className="bg-[#191C18] text-[#C25D54]">SUSPICIOUS Only</option>
                  <option value="NEEDS_REVIEW" className="bg-[#191C18] text-[#D4A359]">NEEDS_REVIEW Only</option>
                  <option value="UNCLASSIFIED" className="bg-[#191C18] text-[#6F736A]">Unclassified</option>
                </select>
              </div>

              {/* Risk Level Filter */}
              <select
                value={riskFilter}
                onChange={(e) => {
                  setRiskFilter(e.target.value);
                  setPage(1);
                }}
                className="bg-[#141713] border border-[#262C24] text-[#F0EEE5] text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-[#A2B89A] font-mono cursor-pointer"
              >
                <option value="ALL" className="bg-[#191C18]">All Risk Levels</option>
                <option value="LOW" className="bg-[#191C18] text-[#8FA887]">LOW Risk</option>
                <option value="MEDIUM" className="bg-[#191C18] text-[#D4A359]">MEDIUM Risk</option>
                <option value="HIGH" className="bg-[#191C18] text-[#C25D54]">HIGH Risk</option>
              </select>

              {/* State Filter */}
              <select
                value={stateFilter}
                onChange={(e) => {
                  setStateFilter(e.target.value);
                  setPage(1);
                }}
                className="bg-[#141713] border border-[#262C24] text-[#F0EEE5] text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-[#A2B89A] font-mono cursor-pointer"
              >
                <option value="ALL" className="bg-[#191C18]">All States</option>
                <option value="PROCESSED" className="bg-[#191C18]">PROCESSED</option>
                <option value="DISCOVERED" className="bg-[#191C18]">DISCOVERED</option>
                <option value="PROCESSING" className="bg-[#191C18]">PROCESSING</option>
                <option value="FAILED" className="bg-[#191C18]">FAILED</option>
              </select>

              {/* Review Filter */}
              <select
                value={reviewFilter}
                onChange={(e) => {
                  setReviewFilter(e.target.value);
                  setPage(1);
                }}
                className="bg-[#141713] border border-[#262C24] text-[#F0EEE5] text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-[#A2B89A] font-mono cursor-pointer"
              >
                <option value="ALL" className="bg-[#191C18]">All Review Status</option>
                <option value="REVIEW_REQUIRED" className="bg-[#191C18] text-[#D4A359]">Review Required</option>
                <option value="NO_REVIEW" className="bg-[#191C18]">No Review</option>
              </select>
            </div>
          </div>

          {/* Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#141713] text-[#6F736A] font-mono text-[10px] uppercase tracking-wider border-b border-[#262C24]">
                <tr>
                  <th className="py-2.5 px-3">Subject / Sender &amp; Summary</th>
                  <th className="py-2.5 px-3">Classification</th>
                  <th className="py-2.5 px-3">Risk Level</th>
                  <th className="py-2.5 px-3">State</th>
                  <th className="py-2.5 px-3">Human Review</th>
                  <th className="py-2.5 px-3">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#262C24] font-sans">
                {emails.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-[#6F736A] font-mono text-xs">
                      No incoming emails match the active filters or search query.
                    </td>
                  </tr>
                ) : (
                  emails.map((email) => {
                    const isSelected = selectedEmail?.message_id === email.message_id;
                    return (
                      <tr
                        key={email.message_id}
                        onClick={() => handleSelectEmail(email)}
                        className={`cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-[#141713] border-l-2 border-l-[#A2B89A]'
                            : 'hover:bg-[#141713]/60'
                        }`}
                      >
                        <td className="py-2.5 px-3 max-w-xs">
                          <div className="font-semibold text-[#F0EEE5] truncate" title={email.subject}>
                            {email.subject || '(No Subject)'}
                          </div>
                          <div className="text-[11px] text-[#A5A69C] font-mono truncate" title={email.sender}>
                            {email.sender}
                          </div>
                          {email.summary ? (
                            <div className="text-[11px] text-[#D0DEC7]/90 line-clamp-1 mt-0.5" title={email.summary}>
                              {email.summary}
                            </div>
                          ) : (
                            <div className="text-[11px] text-[#6F736A] italic line-clamp-1 mt-0.5">
                              Summary unavailable
                            </div>
                          )}
                        </td>

                        <td className="py-2.5 px-3 whitespace-nowrap">
                          {getClassificationBadge(email.classification)}
                        </td>

                        <td className="py-2.5 px-3 whitespace-nowrap">
                          {getRiskBadge(email.risk_level)}
                        </td>

                        <td className="py-2.5 px-3 whitespace-nowrap">
                          {getStateBadge(email.state)}
                        </td>

                        <td className="py-2.5 px-3 whitespace-nowrap">
                          {email.requires_human_review ? (
                            <span className="inline-flex items-center gap-1 text-[#D4A359] font-semibold font-mono text-[11px]">
                              <Eye size={12} /> Required
                            </span>
                          ) : (
                            <span className="text-[#6F736A] font-mono text-[11px]">Automated</span>
                          )}
                        </td>

                        <td className="py-2.5 px-3 whitespace-nowrap text-[#6F736A] font-mono text-[11px]">
                          {email.discovered_at ? email.discovered_at.replace('T', ' ').substring(0, 19) : '-'}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Footer */}
          <div className="p-3 border-t border-[#262C24] bg-[#141713]/60 flex items-center justify-between text-xs text-[#A5A69C] font-mono">
            <div>
              Showing {emails.length > 0 ? (page - 1) * pageSize + 1 : 0} to{' '}
              {Math.min(page * pageSize, totalItems)} of {totalItems} email(s)
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="p-1.5 rounded bg-[#141713] hover:bg-[#191C18] border border-[#262C24] disabled:opacity-30 disabled:pointer-events-none transition-colors"
                title="Previous Page"
              >
                <ChevronLeft size={13} />
              </button>
              <span>
                Page {page} of {totalPages}
              </span>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="p-1.5 rounded bg-[#141713] hover:bg-[#191C18] border border-[#262C24] disabled:opacity-30 disabled:pointer-events-none transition-colors"
                title="Next Page"
              >
                <ChevronRight size={13} />
              </button>
            </div>
          </div>
        </div>

        {/* Detail Inspection Drawer */}
        {selectedEmail && (
          <div className="lg:w-5/12 bg-[#191C18] border border-[#262C24] rounded-xl flex flex-col overflow-hidden">
            {/* Detail Header */}
            <div className="p-4 border-b border-[#262C24] flex justify-between items-start bg-[#141713]/80">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono text-[#A2B89A] font-bold uppercase tracking-wider">
                    Email Security Inspection
                  </span>
                  {getStateBadge(selectedEmail.state)}
                </div>
                <h2 className="text-sm font-bold text-[#F0EEE5] leading-snug">
                  {selectedEmail.subject || '(No Subject)'}
                </h2>
              </div>
              <button
                onClick={() => setSelectedEmail(null)}
                className="text-[#6F736A] hover:text-[#F0EEE5] p-1 rounded hover:bg-[#141713] transition-colors"
              >
                <X size={15} />
              </button>
            </div>

            {/* Detail Content */}
            <div className="p-4 space-y-4 overflow-y-auto max-h-[calc(100vh-220px)] text-xs">
              {loadingDetail && (
                <div className="text-xs text-[#A2B89A] font-mono flex items-center gap-1.5">
                  <RefreshCw size={11} className="animate-spin" /> Fetching fresh detail...
                </div>
              )}

              {/* Classification Banner */}
              <div className="bg-[#141713] border border-[#262C24] rounded-lg p-3 space-y-2">
                <div className="text-[10px] font-mono uppercase text-[#6F736A] font-semibold flex items-center justify-between">
                  <span>AI Security Assessment</span>
                  {getRiskBadge(selectedEmail.risk_level)}
                </div>
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <div>{getClassificationBadge(selectedEmail.classification)}</div>
                  {selectedEmail.requires_human_review && (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#D4A359]/10 text-[#D4A359] border border-[#D4A359]/25 flex items-center gap-1">
                      <Eye size={11} /> MANDATORY HUMAN REVIEW
                    </span>
                  )}
                </div>
              </div>

              {/* AI Email Summary */}
              <div className="space-y-1.5">
                <div className="text-[10px] font-mono uppercase text-[#6F736A] font-semibold tracking-wider flex items-center justify-between">
                  <span className="flex items-center gap-1.5">
                    <FileText size={12} className="text-[#A2B89A]" />
                    AI Natural-Language Summary
                  </span>
                  {selectedEmail.summary ? (
                    <span className="text-[10px] text-[#8FA887] font-mono">Available</span>
                  ) : (
                    <span className="text-[10px] text-[#6F736A] font-mono">Unavailable</span>
                  )}
                </div>
                {selectedEmail.summary ? (
                  <div className="bg-[#141713] border border-[#262C24] rounded-lg p-3 text-[#F0EEE5] text-xs leading-relaxed whitespace-pre-wrap break-words font-sans">
                    {selectedEmail.summary}
                  </div>
                ) : (
                  <div className="bg-[#141713] border border-[#262C24] rounded-lg p-3 text-[#6F736A] italic text-xs">
                    Summary unavailable
                  </div>
                )}
              </div>

              {/* Explanations & Reasons */}
              <div className="space-y-1.5">
                <div className="text-[10px] font-mono uppercase text-[#6F736A] font-semibold tracking-wider">
                  Classification Explanations
                </div>
                {selectedEmail.reasons && selectedEmail.reasons.length > 0 ? (
                  <ul className="space-y-1.5">
                    {selectedEmail.reasons.map((reason, idx) => (
                      <li
                        key={idx}
                        className="bg-[#141713] border border-[#262C24] rounded-lg px-3 py-2 text-[#A5A69C] flex items-start gap-2 leading-relaxed text-xs"
                      >
                        <span className="text-[#A2B89A] font-bold">•</span>
                        <span>{reason}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <div className="bg-[#141713] border border-[#262C24] rounded-lg p-3 text-[#6F736A] italic">
                    {selectedEmail.state === 'PROCESSED'
                      ? 'No specific rationale reported.'
                      : 'Email has not been classified yet. Pending processing cycle.'}
                  </div>
                )}
              </div>

              {/* Metadata Fields */}
              <div className="space-y-1.5">
                <div className="text-[10px] font-mono uppercase text-[#6F736A] font-semibold tracking-wider">
                  Email Metadata
                </div>
                <div className="bg-[#141713] border border-[#262C24] rounded-lg p-3 space-y-2 font-mono text-[11px]">
                  <div className="flex justify-between items-center py-0.5">
                    <span className="text-[#6F736A] flex items-center gap-1">
                      <Hash size={11} /> Message ID:
                    </span>
                    <span className="text-[#F0EEE5] truncate max-w-xs" title={selectedEmail.message_id}>
                      {selectedEmail.message_id}
                    </span>
                  </div>

                  {selectedEmail.thread_id && (
                    <div className="flex justify-between items-center py-0.5 border-t border-[#262C24]">
                      <span className="text-[#6F736A]">Thread ID:</span>
                      <span className="text-[#F0EEE5] truncate max-w-xs">{selectedEmail.thread_id}</span>
                    </div>
                  )}

                  <div className="flex justify-between items-center py-0.5 border-t border-[#262C24]">
                    <span className="text-[#6F736A] flex items-center gap-1">
                      <User size={11} /> Sender:
                    </span>
                    <span className="text-[#F0EEE5] truncate max-w-xs" title={selectedEmail.sender}>
                      {selectedEmail.sender}
                    </span>
                  </div>

                  <div className="flex justify-between items-center py-0.5 border-t border-[#262C24]">
                    <span className="text-[#6F736A] flex items-center gap-1">
                      <Calendar size={11} /> Date:
                    </span>
                    <span className="text-[#F0EEE5]">{selectedEmail.date || '-'}</span>
                  </div>

                  <div className="flex justify-between items-center py-0.5 border-t border-[#262C24]">
                    <span className="text-[#6F736A]">Discovered At:</span>
                    <span className="text-[#A5A69C]">{selectedEmail.discovered_at}</span>
                  </div>

                  {selectedEmail.processed_at && (
                    <div className="flex justify-between items-center py-0.5 border-t border-[#262C24]">
                      <span className="text-[#6F736A]">Processed At:</span>
                      <span className="text-[#A5A69C]">{selectedEmail.processed_at}</span>
                    </div>
                  )}

                  <div className="flex justify-between items-center py-0.5 border-t border-[#262C24]">
                    <span className="text-[#6F736A]">Retry Count:</span>
                    <span className="text-[#A5A69C]">{selectedEmail.retry_count}</span>
                  </div>
                </div>
              </div>

              {/* Untrusted Snippet (Safe Text Escaped) */}
              <div className="space-y-1.5">
                <div className="text-[10px] font-mono uppercase text-[#6F736A] font-semibold tracking-wider flex items-center gap-1.5">
                  <Lock size={11} className="text-[#D4A359]" />
                  <span>Untrusted Email Snippet</span>
                  <span className="text-[#6F736A] lowercase text-[10px]">(sanitized read-only)</span>
                </div>
                <div className="bg-[#101210] border border-[#262C24] rounded-lg p-3 font-mono text-[11px] text-[#A5A69C] whitespace-pre-wrap break-words leading-relaxed max-h-40 overflow-y-auto">
                  {selectedEmail.snippet ? selectedEmail.snippet : '(Empty snippet)'}
                </div>
              </div>

              {/* Failure / Error Detail if present */}
              {(selectedEmail.last_error || selectedEmail.failure_reason) && (
                <div className="space-y-1">
                  <div className="text-[10px] font-mono uppercase text-[#C25D54] font-semibold tracking-wider flex items-center gap-1">
                    <AlertCircle size={11} /> Processing Failure Info
                  </div>
                  <div className="bg-[#C25D54]/10 border border-[#C25D54]/25 rounded-lg p-2.5 text-[#C25D54] font-mono text-[11px] break-words">
                    {selectedEmail.failure_reason || selectedEmail.last_error}
                  </div>
                </div>
              )}

              {/* Advisory Disclaimer */}
              <div className="bg-[#141713] border border-[#262C24] rounded-lg p-3 text-[11px] text-[#A5A69C] flex items-start gap-2.5">
                <Info size={13} className="text-[#A2B89A] shrink-0 mt-0.5" />
                <span className="leading-relaxed">
                  <strong className="text-[#F0EEE5]">Phase 3 Read-Only Perimeter:</strong> Inspecting or reviewing
                  this email does not authorize tool execution or send automated replies. Downstream mutations remain
                  gated by VETO Gateway&apos;s human approval workflow.
                </span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
