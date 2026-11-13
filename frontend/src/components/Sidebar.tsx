import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Home,
  Shield,
  CheckSquare,
  List,
  TrendingUp,
  BarChart3,
  GitFork,
  Mail,
  X,
} from 'lucide-react';
import vetoEmblem from '../assets/veto_emblem.png';
import sidebarWaves from '../assets/sidebar_waves_2x.png';

interface SidebarProps {
  isOpen?: boolean;
  onClose?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ isOpen, onClose }) => {
  const navItems = [
    { to: '/', icon: <Home size={14} />, label: 'Overview' },
    { to: '/decisions', icon: <Shield size={14} />, label: 'Decisions' },
    { to: '/approvals', icon: <CheckSquare size={14} />, label: 'Approvals' },
    { to: '/audit', icon: <List size={14} />, label: 'Audit Trail' },
    { to: '/evaluation', icon: <TrendingUp size={14} />, label: 'Evaluation' },
    { to: '/benchmarks', icon: <BarChart3 size={14} />, label: 'Benchmarks' },
    { to: '/security/cross-service', icon: <GitFork size={14} />, label: 'Cross-Service' },
    { to: '/emails', icon: <Mail size={14} />, label: 'Incoming Emails' },
  ];

  return (
    <>
      {/* Mobile Drawer Backdrop */}
      {isOpen && (
        <div
          onClick={onClose}
          className="fixed inset-0 bg-black/70 backdrop-blur-xs z-40 md:hidden transition-opacity"
          aria-hidden="true"
        />
      )}

      <aside
        className={`
          fixed md:static top-0 bottom-0 left-0 z-50
          w-[148px] xl:w-[168px] bg-[#101210] border-r border-[#262C24]
          flex flex-col justify-between shrink-0 transition-transform duration-200 ease-in-out select-none
          ${isOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'}
        `}
      >
        <div className="flex flex-col">
          {/* Brand Header */}
          <div className="px-4 pt-5 pb-5 flex items-start justify-between">
            <div className="flex flex-col">
              <div className="flex items-center gap-2.5">
                <img
                  src={vetoEmblem}
                  alt="VETO emblem"
                  className="w-4 h-4.5 object-contain shrink-0"
                />
                <span className="font-serif text-[17px] tracking-[0.25em] text-[#F0EEE5] font-normal leading-none pl-0.5">
                  VETO
                </span>
              </div>
              <div className="text-[7.5px] font-mono tracking-[0.2em] text-[#6F736A] pt-2 uppercase leading-none">
                AI AGENT SECURITY GATEWAY
              </div>
            </div>

            {/* Mobile close button */}
            <button
              onClick={onClose}
              className="lg:hidden p-1 text-[#A5A69C] hover:text-[#F0EEE5] rounded hover:bg-[#191C18]"
              aria-label="Close navigation"
            >
              <X size={15} />
            </button>
          </div>

          {/* Navigation List */}
          <nav className="px-2 space-y-0.5">
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                onClick={() => onClose && onClose()}
                className={({ isActive }) =>
                  `flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-xs transition-all ${
                    isActive
                      ? 'bg-[#191C18] border border-[#262C24] text-[#F0EEE5] font-medium shadow-xs'
                      : 'text-[#A5A69C] hover:text-[#F0EEE5] hover:bg-[#141713] border border-transparent'
                  }`
                }
              >
                <span className="shrink-0 text-[#A2B89A]/90">{item.icon}</span>
                <span className="truncate">{item.label}</span>
              </NavLink>
            ))}
          </nav>
        </div>

        {/* System Health & Wave Graphic at bottom */}
        <div className="relative overflow-hidden pt-4">
          <div className="px-4 pb-2 relative z-10 space-y-0.5">
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[#8FA887] shadow-[0_0_8px_#8FA887] animate-pulse" />
              <span className="text-[11px] font-medium text-[#F0EEE5]">
                System Healthy
              </span>
            </div>
            <div className="text-[9.5px] text-[#6F736A] font-sans pl-3">
              All services operational
            </div>
          </div>

          {/* Wave line graphic */}
          <div className="w-full h-16 pointer-events-none select-none overflow-hidden relative">
            <img
              src={sidebarWaves}
              alt=""
              aria-hidden="true"
              className="w-full h-full object-cover object-bottom opacity-75"
            />
          </div>
        </div>
      </aside>
    </>
  );
};