import React, { useState, useEffect, useRef } from 'react';
import { Sidebar } from '../components/Sidebar';
import { CustomCursor } from '../components/CustomCursor';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import { Search, Bell, ChevronDown, Menu, CheckCircle2, ShieldAlert } from 'lucide-react';
import { getDecisions, getEmails } from '../services/api';
import type { SecurityDecision, EmailRecord } from '../types';

export const Layout: React.FC = () => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<{
    decisions: SecurityDecision[];
    emails: EmailRecord[];
  }>({ decisions: [], emails: [] });
  const [searchOpen, setSearchOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const searchRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const location = useLocation();
  const isOverview = location.pathname === '/';

  // Keyboard shortcut Cmd/Ctrl + K to focus search
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        searchInputRef.current?.focus();
        setSearchOpen(true);
      }
      if (e.key === 'Escape') {
        setSearchOpen(false);
        setNotificationsOpen(false);
        setProfileOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Handle outside click for dropdowns
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (searchRef.current && !searchRef.current.contains(e.target as Node)) {
        setSearchOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Search API querying
  useEffect(() => {
    if (!searchQuery.trim()) {
      setSearchResults({ decisions: [], emails: [] });
      return;
    }

    const timer = setTimeout(async () => {
      try {
        const [decisions, emailRes] = await Promise.all([
          getDecisions().catch(() => []),
          getEmails({ search: searchQuery }).catch(() => ({ emails: [], total: 0 })),
        ]);

        const filteredDecisions = decisions.filter(
          (d) =>
            d.operation?.toLowerCase().includes(searchQuery.toLowerCase()) ||
            d.agent_id?.toLowerCase().includes(searchQuery.toLowerCase()) ||
            d.reason?.toLowerCase().includes(searchQuery.toLowerCase())
        ).slice(0, 4);

        setSearchResults({
          decisions: filteredDecisions,
          emails: (emailRes.emails || []).slice(0, 4),
        });
      } catch {
        // quiet error
      }
    }, 150);

    return () => clearTimeout(timer);
  }, [searchQuery]);

  return (
    <div className="flex h-screen bg-[#101210] text-[#F0EEE5] overflow-hidden font-sans">
      <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      <div className="flex-1 flex flex-col min-w-0 overflow-hidden relative">
        {/* Top Utility Bar (Overlay across central content area) */}
        <header className="absolute top-0 left-0 right-0 h-10 pl-6 pr-3.5 flex items-center justify-between z-30 select-none bg-transparent pointer-events-none">
          {/* Mobile hamburger & Central Search Area */}
          <div className="flex items-center gap-3 flex-1 max-w-xl pointer-events-auto">
            <button
              onClick={() => setSidebarOpen(true)}
              className="md:hidden p-1.5 rounded text-[#A5A69C] hover:text-[#F0EEE5] hover:bg-[#191C18] border border-[#262C24] transition-colors"
              aria-label="Open navigation"
            >
              <Menu size={16} />
            </button>

            {/* Search Input matching Reference */}
            <div ref={searchRef} className="relative w-full max-w-[365px]">
              <div className="relative flex items-center">
                <Search
                  size={12}
                  className="absolute left-3 text-[#6F736A] pointer-events-none"
                />
                <input
                  ref={searchInputRef}
                  type="text"
                  placeholder="Search decisions, emails, agents, or operations..."
                  value={searchQuery}
                  onFocus={() => setSearchOpen(true)}
                  onChange={(e) => {
                    setSearchQuery(e.target.value);
                    setSearchOpen(true);
                  }}
                  className="w-full h-7 pl-8 pr-10 bg-[#141713] border border-[#262C24] rounded-lg text-xs text-[#F0EEE5] placeholder-[#6F736A] focus:outline-none focus:border-[#343B32] transition-colors font-sans"
                />
                <div className="absolute right-2 px-1.5 py-0.5 rounded border border-[#262C24] text-[9px] font-mono text-[#6F736A] pointer-events-none select-none bg-[#101210]/60">
                  ⌘ K
                </div>
              </div>

              {/* Functional Search Dropdown Results */}
              {searchOpen && searchQuery.trim() && (
                <div className="absolute top-9 left-0 right-0 bg-[#141713] border border-[#262C24] rounded-xl shadow-2xl p-2 z-50 text-xs font-mono space-y-2 max-h-80 overflow-y-auto">
                  {searchResults.decisions.length === 0 && searchResults.emails.length === 0 ? (
                    <div className="p-3 text-center text-[#6F736A]">
                      No matching records found.
                    </div>
                  ) : (
                    <>
                      {searchResults.decisions.length > 0 && (
                        <div>
                          <div className="px-2 py-1 text-[9px] text-[#6F736A] uppercase tracking-wider">
                            Decisions
                          </div>
                          {searchResults.decisions.map((d) => (
                            <div
                              key={d.event_id}
                              onClick={() => {
                                navigate('/decisions');
                                setSearchOpen(false);
                              }}
                              className="px-2 py-1.5 rounded hover:bg-[#191C18] cursor-pointer flex items-center justify-between text-[#F0EEE5]"
                            >
                              <span className="truncate">{d.operation}</span>
                              <span
                                className={`text-[10px] font-bold ${
                                  d.final_decision === 'ALLOW'
                                    ? 'text-[#8FA887]'
                                    : d.final_decision === 'BLOCK'
                                    ? 'text-[#C25D54]'
                                    : 'text-[#D4A359]'
                                }`}
                              >
                                {d.final_decision}
                              </span>
                            </div>
                          ))}
                        </div>
                      )}

                      {searchResults.emails.length > 0 && (
                        <div className="border-t border-[#262C24] pt-1">
                          <div className="px-2 py-1 text-[9px] text-[#6F736A] uppercase tracking-wider">
                            Emails
                          </div>
                          {searchResults.emails.map((m) => (
                            <div
                              key={m.message_id}
                              onClick={() => {
                                navigate('/emails');
                                setSearchOpen(false);
                              }}
                              className="px-2 py-1.5 rounded hover:bg-[#191C18] cursor-pointer flex items-center justify-between text-[#F0EEE5]"
                            >
                              <span className="truncate">{m.subject || m.message_id}</span>
                              <span className="text-[10px] text-[#A2B89A]">
                                {m.security_classification}
                              </span>
                            </div>
                          ))}
                        </div>
                      )}
                    </>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Right Profile & Notifications Area */}
          <div className="flex items-center gap-3.5 pointer-events-auto">
            {/* Notification Bell */}
            <div className="relative">
              <button
                onClick={() => setNotificationsOpen(!notificationsOpen)}
                className="relative p-1 text-[#A5A69C] hover:text-[#F0EEE5] transition-colors rounded-full"
                aria-label="View notifications"
              >
                <Bell size={15} />
                <span className="absolute top-0.5 right-0.5 w-1.5 h-1.5 rounded-full bg-[#8FA887] shadow-[0_0_4px_#8FA887]" />
              </button>

              {notificationsOpen && (
                <div className="absolute right-0 top-8 w-64 bg-[#141713] border border-[#262C24] rounded-xl shadow-2xl p-3 z-50 text-xs font-mono space-y-2">
                  <div className="flex items-center justify-between pb-1.5 border-b border-[#262C24] text-[10px] uppercase text-[#6F736A]">
                    <span>Security Alerts</span>
                    <span className="text-[#8FA887]">Live</span>
                  </div>
                  <div className="space-y-1.5 text-[11px]">
                    <div className="p-1.5 rounded bg-[#191C18] flex items-center gap-2 text-[#F0EEE5]">
                      <CheckCircle2 size={12} className="text-[#8FA887] shrink-0" />
                      <span className="truncate">All 8 security layers operational</span>
                    </div>
                    <div className="p-1.5 rounded bg-[#191C18] flex items-center gap-2 text-[#A5A69C]">
                      <ShieldAlert size={12} className="text-[#D4A359] shrink-0" />
                      <span className="truncate">1 approval pending review</span>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* User Profile Badge */}
            <div className="relative">
              <button
                onClick={() => setProfileOpen(!profileOpen)}
                className="flex items-center gap-1.5 py-0.5 rounded-full hover:bg-[#141713] transition-colors"
                aria-label="User menu"
              >
                <div className="w-6 h-6 rounded-full bg-[#E5E0D5] text-[#101210] font-sans font-semibold text-[10.5px] flex items-center justify-center shrink-0">
                  AB
                </div>
                <span className="text-xs font-medium text-[#F0EEE5] hidden sm:inline pl-0.5">
                  Aashikaa
                </span>
                <ChevronDown size={11} className="text-[#6F736A]" />
              </button>

              {profileOpen && (
                <div className="absolute right-0 top-8 w-44 bg-[#141713] border border-[#262C24] rounded-xl shadow-2xl p-2 z-50 text-xs font-mono space-y-1">
                  <div className="px-2.5 py-1.5 text-[11px] text-[#F0EEE5] font-semibold border-b border-[#262C24]">
                    Aashikaa
                    <div className="text-[9px] text-[#6F736A] font-normal">Security Administrator</div>
                  </div>
                  <button
                    onClick={() => {
                      navigate('/');
                      setProfileOpen(false);
                    }}
                    className="w-full text-left px-2.5 py-1 rounded text-[#A5A69C] hover:text-[#F0EEE5] hover:bg-[#191C18] text-[11px]"
                  >
                    Overview
                  </button>
                  <button
                    onClick={() => {
                      navigate('/audit');
                      setProfileOpen(false);
                    }}
                    className="w-full text-left px-2.5 py-1 rounded text-[#A5A69C] hover:text-[#F0EEE5] hover:bg-[#191C18] text-[11px]"
                  >
                    Audit Ledger
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        {/* Main Content Area */}
        <main className={`flex-1 h-full flex flex-col overflow-y-auto px-6 pb-4 bg-[#101210] ${isOverview ? 'pt-0' : 'pt-12'}`}>
          <Outlet />
        </main>
      </div>

      <CustomCursor />
    </div>
  );
};