import React from 'react';
import {
  Layers,
  Shield,
  Compass,
  AlertTriangle,
  FileCode,
  ShieldCheck,
  Database,
  Check,
} from 'lucide-react';

export const PipelineVisualization: React.FC = () => {
  const stages = [
    {
      id: 'prov',
      label: 'Provenance',
      status: 'Verified',
      hasCheck: true,
      icon: <Layers size={12} className="text-[#A2B89A]" />,
    },
    {
      id: 'cap',
      label: 'Capability',
      status: 'Allowed',
      hasCheck: false,
      icon: <Shield size={12} className="text-[#A2B89A]" />,
    },
    {
      id: 'dest',
      label: 'Destination',
      status: 'Trusted',
      hasCheck: true,
      icon: <Compass size={12} className="text-[#A2B89A]" />,
    },
    {
      id: 'risk',
      label: 'Risk',
      status: 'Low',
      hasCheck: false,
      icon: <AlertTriangle size={12} className="text-[#A2B89A]" />,
    },
    {
      id: 'ctx',
      label: 'Context',
      status: 'Valid',
      hasCheck: false,
      icon: <FileCode size={12} className="text-[#A2B89A]" />,
    },
    {
      id: 'final',
      label: 'Final Decision',
      status: 'Allowed',
      hasCheck: false,
      icon: <ShieldCheck size={12} className="text-[#A2B89A]" />,
    },
  ];

  return (
    <div className="w-full bg-[#141713] border border-[#262C24] rounded-2xl px-5 py-3 select-none">
      {/* Header */}
      <div className="flex items-center gap-2 mb-2.5">
        <span className="text-[9.5px] font-mono uppercase tracking-[0.2em] text-[#A5A69C] font-semibold">
          SECURITY PIPELINE
        </span>
        <div className="flex items-center gap-1 text-[9.5px] font-mono text-[#8FA887]">
          <span className="w-1.5 h-1.5 rounded-full bg-[#8FA887] shadow-[0_0_6px_#8FA887]" />
          <span>Live</span>
        </div>
      </div>

      {/* Main Track & Downstream Execution Row */}
      <div className="flex items-center justify-between gap-4">
        {/* Stages Track */}
        <div className="flex-1 relative">
          {/* Thin connecting guide line */}
          <div
            className="absolute top-[14px] left-[7%] right-[7%] h-[1px] bg-[#262C24]"
            aria-hidden="true"
          />

          <div className="grid grid-cols-6 gap-1 relative z-10">
            {stages.map((stg) => (
              <div key={stg.id} className="flex flex-col items-center text-center">
                {/* Circular Icon Container */}
                <div className="w-7 h-7 rounded-full bg-[#191C18] border border-[#262C24] flex items-center justify-center shadow-xs">
                  {stg.icon}
                </div>

                {/* Stage Name */}
                <span className="mt-1 text-[10.5px] font-sans font-medium text-[#F0EEE5] truncate max-w-full leading-tight">
                  {stg.label}
                </span>

                {/* Stage Status */}
                <span className="text-[9px] font-mono text-[#A2B89A] flex items-center justify-center gap-0.5 mt-0.5 leading-none">
                  {stg.hasCheck && <Check size={9} className="shrink-0 stroke-[2.5]" />}
                  <span>{stg.status}</span>
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Vertical Divider */}
        <div className="w-[1px] h-11 bg-[#262C24] shrink-0 mx-2" />

        {/* Downstream Execution Panel on Right */}
        <div className="shrink-0 flex flex-col space-y-1">
          <div className="text-[8.5px] font-mono uppercase tracking-wider text-[#6F736A]">
            DOWNSTREAM EXECUTION
          </div>
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-full bg-[#191C18] border border-[#262C24] flex items-center justify-center shrink-0">
              <Database size={12} className="text-[#A2B89A]" />
            </div>
            <div className="flex flex-col">
              <span className="text-[11px] font-medium text-[#F0EEE5] leading-tight">Executed</span>
              <span className="text-[9px] font-mono text-[#8FA887] flex items-center gap-1 leading-tight">
                <span className="w-1.5 h-1.5 rounded-full bg-[#8FA887]" />
                2.3s
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};