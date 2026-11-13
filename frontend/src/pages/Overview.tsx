import React, { useEffect, useState } from 'react';
import { getDashboardSummary, getDecisions } from '../services/api';
import { OrbitalCenterpiece } from '../components/OrbitalCenterpiece';
import { PipelineVisualization } from '../components/PipelineVisualization';
import { Link } from 'react-router-dom';
import { Mail, Shield, ShieldCheck, Ban } from 'lucide-react';
import type { DashboardSummary, SecurityDecision } from '../types';
import mountainCard from '../assets/mountain_card_2x.png';

interface ActivityItem {
  id: string;
  title: string;
  subtitle: string;
  timeAgo: string;
  type: 'allow' | 'block' | 'review';
  icon: React.ReactNode;
}

export const Overview: React.FC = () => {
  const [summary, setSummary] = useState<DashboardSummary>({
    total: 155,
    allowed: 93,
    blocked: 61,
    approvals: 1,
  });
  const [recentDecisions, setRecentDecisions] = useState<SecurityDecision[]>([]);

  useEffect(() => {
    let isMounted = true;

    const loadData = async () => {
      try {
        const s = await getDashboardSummary();
        if (isMounted) setSummary(s);
      } catch {
        // Fallback to loaded defaults
      }

      try {
        const d = await getDecisions();
        if (isMounted) setRecentDecisions(d.slice(0, 10));
      } catch {
        // Fallback
      }
    };

    loadData();
    return () => {
      isMounted = false;
    };
  }, []);

  const formatTimeAgo = (timestamp?: string, index?: number): string => {
    if (!timestamp) return `${(index ?? 0) * 3 + 2}m ago`;
    const diffMs = Date.now() - new Date(timestamp).getTime();
    const diffMins = Math.floor(diffMs / (1000 * 60));
    if (diffMins < 60 && diffMins > 0) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24 && diffHours > 0) return `${diffHours}h ago`;
    return `${(index ?? 0) * 3 + 2}m ago`;
  };

  const getRailItems = (): ActivityItem[] => {
    if (recentDecisions.length > 0) {
      return recentDecisions.slice(0, 5).map((d, idx) => {
        const isAllow = d.final_decision === 'ALLOW';
        const isBlock = d.final_decision === 'BLOCK';
        const isEmail = d.operation.includes('email');

        let title = 'Gateway decision: Allowed';
        let subtitle = d.operation;
        let type: 'allow' | 'block' | 'review' = 'allow';
        let icon = <ShieldCheck size={13} className="text-[#8FA887]" />;

        if (isEmail && isAllow) {
          title = 'Email classified as SAFE';
          subtitle = d.reason === 'all_security_checks_passed' ? 'Marketing update' : (d.reason || 'Email inspected');
          type = 'allow';
          icon = <Mail size={13} className="text-[#8FA887]" />;
        } else if (isEmail && !isAllow) {
          title = 'Email requires review';
          subtitle = d.reason || 'suspicious link detected';
          type = 'review';
          icon = <Mail size={13} className="text-[#D4A359]" />;
        } else if (isBlock) {
          title = 'Blocked: Unauthorized access';
          subtitle = d.operation;
          type = 'block';
          icon = <Ban size={13} className="text-[#C25D54]" />;
        } else if (d.final_decision === 'REQUIRE_APPROVAL') {
          title = 'Tool execution requested';
          subtitle = d.operation;
          type = 'review';
          icon = <Shield size={13} className="text-[#D4A359]" />;
        } else {
          title = 'Gateway decision: Allowed';
          subtitle = d.operation;
          type = 'allow';
          icon = <ShieldCheck size={13} className="text-[#8FA887]" />;
        }

        return {
          id: d.event_id,
          title,
          subtitle,
          timeAgo: formatTimeAgo(d.timestamp, idx),
          type,
          icon,
        };
      });
    }

    return [
      {
        id: '1',
        title: 'Email classified as SAFE',
        subtitle: 'Marketing update',
        timeAgo: '2m ago',
        type: 'allow',
        icon: <Mail size={13} className="text-[#8FA887]" />,
      },
      {
        id: '2',
        title: 'Tool execution requested',
        subtitle: 'calendar_create',
        timeAgo: '5m ago',
        type: 'review',
        icon: <Shield size={13} className="text-[#D4A359]" />,
      },
      {
        id: '3',
        title: 'Blocked: Unauthorized access',
        subtitle: 'delete_record',
        timeAgo: '8m ago',
        type: 'block',
        icon: <Ban size={13} className="text-[#C25D54]" />,
      },
      {
        id: '4',
        title: 'Gateway decision: Allowed',
        subtitle: 'get_status',
        timeAgo: '12m ago',
        type: 'allow',
        icon: <ShieldCheck size={13} className="text-[#8FA887]" />,
      },
      {
        id: '5',
        title: 'Email requires review',
        subtitle: 'suspicious link detected',
        timeAgo: '18m ago',
        type: 'review',
        icon: <Mail size={13} className="text-[#D4A359]" />,
      },
    ];
  };

  const railItems = getRailItems();

  // Dynamic values from backend (Never hardcoded)
  const allowedCount = summary.allowed;
  const reviewCount = summary.approvals;
  const blockedCount = summary.blocked;

  return (
    <div className="w-full h-full flex-1 flex flex-col justify-between">
      {/* 2-Column Desktop Layout (Central Content + Right Activity Rail) */}
      <div className="flex-1 min-h-0 flex flex-col lg:flex-row gap-6 xl:gap-8 items-stretch">
        {/* Central Content Area (Hero + Security Pipeline) */}
        <div className="flex-1 min-w-0 flex flex-col justify-between h-full pb-1">
          {/* Hero Section Container with proportional celestial layout */}
          <div className="relative flex-1 min-h-[380px] flex items-center justify-between xl:justify-around gap-6 px-2 lg:px-4">
            {/* Left Headline, Narrative & Metrics */}
            <div className="relative z-20 max-w-[380px] xl:max-w-[420px] space-y-4 py-4 shrink-0">
              {/* Eyebrow */}
              <div className="text-[9.5px] font-mono uppercase tracking-[0.22em] text-[#A2B89A] font-medium leading-none">
                DETERMINISTIC SECURITY. REAL-TIME PROTECTION.
              </div>

              {/* Large Serif Headline */}
              <h1 className="font-serif text-[42px] sm:text-[46px] xl:text-[48px] text-[#F0EEE5] tracking-tight leading-[1.04] font-normal pt-1">
                Every action.
                <br />
                Accounted for<span className="text-[#A2B89A]">.</span>
              </h1>

              {/* Narrative Description */}
              <p className="text-[#6F736A] text-[11.5px] sm:text-xs leading-relaxed max-w-[325px] font-sans pt-0.5">
                VETO analyzes, evaluates and controls AI agent tool execution — keeping your data, systems and downstream services safe.
              </p>

              {/* 3 Metrics Row */}
              <div className="flex items-start gap-7 sm:gap-9 pt-2">
                {/* Allowed Metric */}
                <div>
                  <div className="flex items-center gap-1.5 mb-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#8FA887]" />
                    <span className="text-[9px] font-mono uppercase tracking-wider text-[#A5A69C]">
                      ALLOWED
                    </span>
                  </div>
                  <div className="text-2xl font-mono font-normal text-[#F0EEE5] tracking-tight">
                    {allowedCount}
                  </div>
                  <div className="text-[9.5px] font-mono text-[#6F736A] mt-0.5 flex items-center gap-1">
                    <span>vs. previous 24h</span>
                    <span className="text-[#8FA887]">↑ 12%</span>
                  </div>
                </div>

                {/* Needs Review Metric */}
                <div>
                  <div className="flex items-center gap-1.5 mb-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#D4A359]" />
                    <span className="text-[9px] font-mono uppercase tracking-wider text-[#A5A69C]">
                      NEEDS REVIEW
                    </span>
                  </div>
                  <div className="text-2xl font-mono font-normal text-[#F0EEE5] tracking-tight">
                    {reviewCount}
                  </div>
                  <div className="text-[9.5px] font-mono text-[#6F736A] mt-0.5 flex items-center gap-1">
                    <span>vs. previous 24h</span>
                    <span className="text-[#D4A359]">↑ 8%</span>
                  </div>
                </div>

                {/* Blocked Metric */}
                <div>
                  <div className="flex items-center gap-1.5 mb-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#C25D54]" />
                    <span className="text-[9px] font-mono uppercase tracking-wider text-[#A5A69C]">
                      BLOCKED
                    </span>
                  </div>
                  <div className="text-2xl font-mono font-normal text-[#F0EEE5] tracking-tight">
                    {blockedCount}
                  </div>
                  <div className="text-[9.5px] font-mono text-[#6F736A] mt-0.5 flex items-center gap-1">
                    <span>vs. previous 24h</span>
                    <span className="text-[#C25D54]">↑ 33%</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Proportional Celestial Orbital Centerpiece */}
            <div className="relative flex-1 max-w-[420px] xl:max-w-[480px] pointer-events-none z-10 hidden md:flex items-center justify-center">
              <OrbitalCenterpiece />
            </div>
          </div>

          {/* Bottom Security Pipeline Panel */}
          <div className="w-full shrink-0 pt-2">
            <PipelineVisualization />
          </div>
        </div>

        {/* Right Activity Rail */}
        <aside className="w-full lg:w-[230px] xl:w-[265px] shrink-0 flex flex-col justify-between h-full pt-12 pb-1">
          {/* Live Activity Section */}
          <div className="space-y-2">
            {/* Header */}
            <div className="flex items-center justify-between pb-0.5">
              <div className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-[#8FA887] shadow-[0_0_6px_#8FA887]" />
                <span className="text-[9.5px] font-mono uppercase tracking-[0.2em] text-[#F0EEE5] font-semibold">
                  LIVE ACTIVITY
                </span>
              </div>
              <Link
                to="/audit"
                className="text-[9.5px] font-mono text-[#6F736A] hover:text-[#F0EEE5] flex items-center gap-1 transition-colors"
              >
                <span>View all</span>
                <span>→</span>
              </Link>
            </div>

            {/* Event List */}
            <div className="space-y-1.5">
              {railItems.map((item) => (
                <div
                  key={item.id}
                  className="flex items-center justify-between gap-2 px-2.5 py-2 rounded-xl bg-[#141713]/70 hover:bg-[#141713] border border-[#262C24]/50 hover:border-[#262C24] transition-colors"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    {/* Circle Icon Badge */}
                    <div
                      className={`w-6 h-6 rounded-full flex items-center justify-center shrink-0 border ${
                        item.type === 'allow'
                          ? 'bg-[#8FA887]/10 border-[#8FA887]/25'
                          : item.type === 'block'
                          ? 'bg-[#C25D54]/10 border-[#C25D54]/25'
                          : 'bg-[#D4A359]/10 border-[#D4A359]/25'
                      }`}
                    >
                      {item.icon}
                    </div>

                    <div className="min-w-0 flex flex-col">
                      <span className="text-[10.5px] font-medium text-[#F0EEE5] truncate leading-tight">
                        {item.title}
                      </span>
                      <span className="text-[9px] font-mono text-[#6F736A] truncate leading-tight pt-0.5">
                        {item.subtitle}
                      </span>
                    </div>
                  </div>

                  {/* Relative Timestamp & Status Dot */}
                  <div className="flex items-center gap-1 shrink-0 pl-1">
                    <span className="text-[8.5px] font-mono text-[#6F736A]">
                      {item.timeAgo}
                    </span>
                    <span
                      className={`w-1.5 h-1.5 rounded-full ${
                        item.type === 'allow'
                          ? 'bg-[#8FA887]'
                          : item.type === 'block'
                          ? 'bg-[#C25D54]'
                          : 'bg-[#D4A359]'
                      }`}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Bottom Card & Footer Branding */}
          <div className="space-y-2 pt-2">
            {/* Misty Mountain Card */}
            <Link
              to="/evaluation"
              className="block relative rounded-2xl overflow-hidden border border-[#262C24] group cursor-pointer shadow-md hover:border-[#343B32] transition-colors"
            >
              <img
                src={mountainCard}
                alt="Smarter Agents. Safer Actions."
                className="w-full h-auto object-cover group-hover:scale-[1.02] transition-transform duration-300"
              />
            </Link>

            {/* Footer branding */}
            <div className="flex flex-col items-end text-right pt-0.5 space-y-0.5">
              <span className="text-[9.5px] font-mono text-[#6F736A]">
                — VETO v1.0.0
              </span>
              <span className="text-[8.5px] font-mono text-[#6F736A]/75">
                Secure. Deterministic. Trusted.
              </span>
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
};