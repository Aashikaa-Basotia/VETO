import React, { useState } from 'react';
import { ArrowDown, CheckCircle2, XCircle, Info, Shield, Layers } from 'lucide-react';

export const CrossService: React.FC = () => {
  const [activeTab, setActiveTab] = useState(0);

  const scenarios = [
    {
      title: "Gmail → Calendar Mismatch",
      capability: "list_recent_emails",
      expectedDest: "gmail_api",
      requestedDest: "google_calendar_api",
      decision: "BLOCK",
      reason: "unknown_destination",
      downstream: "NOT CONTACTED",
      explanation: "Agent requests Gmail capability (list_recent_emails) but targets Calendar destination (google_calendar_api). VETO enforces strict 1:1 binding at Layer 4 and prevents cross-service confused-deputy calls."
    },
    {
      title: "Calendar → Gmail Mismatch",
      capability: "list_calendar_events",
      expectedDest: "google_calendar_api",
      requestedDest: "gmail_api",
      decision: "BLOCK",
      reason: "unknown_destination",
      downstream: "NOT CONTACTED",
      explanation: "Agent requests Calendar capability (list_calendar_events) but targets Gmail destination. VETO prevents capability hijacking across isolated service perimeters."
    },
    {
      title: "Valid In-Bounds Request",
      capability: "list_recent_emails",
      expectedDest: "gmail_api",
      requestedDest: "gmail_api",
      decision: "ALLOW",
      reason: "all_security_checks_passed",
      downstream: "CONTACTED",
      explanation: "Capability and destination strictly match the allowlist policy. Request traverses all 7 security layers to reach the downstream adapter."
    }
  ];

  const scenario = scenarios[activeTab];

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="text-center space-y-2 mb-6">
        <div className="text-[9.5px] font-mono tracking-[0.22em] text-[#A2B89A] uppercase font-medium">
          SPECIFICATION MODEL &amp; VERIFICATION
        </div>
        <h1 className="font-serif text-2xl lg:text-3xl font-normal text-[#F0EEE5] tracking-tight">Cross-Service Security Isolation</h1>
        <p className="text-[#A5A69C] text-xs max-w-lg mx-auto">
          VETO enforces deterministic capability-to-destination mappings to prevent confused-deputy privilege confusion between external services.
        </p>
        <p className="text-[10px] text-[#6F736A] font-mono">
          Note: Real Gmail OAuth integration is verified in test mode; mock adapters model live service boundaries.
        </p>
      </div>

      {/* Scenario Selector Tabs */}
      <div className="flex justify-center gap-2 mb-6 flex-wrap">
        {scenarios.map((s, idx) => (
          <button
            key={idx}
            onClick={() => setActiveTab(idx)}
            className={`px-3.5 py-1.5 rounded-lg font-mono text-xs transition-all border ${
              activeTab === idx
                ? 'bg-[#A2B89A] text-[#101210] font-bold border-[#A2B89A] shadow-sm'
                : 'bg-[#141713] text-[#A5A69C] border-[#262C24] hover:border-[#343B32] hover:text-[#F0EEE5]'
            }`}
          >
            {s.title}
          </button>
        ))}
      </div>

      {/* Visual Architectural Flow */}
      <div className="bg-[#191C18] border border-[#262C24] rounded-xl p-6 md:p-8 relative overflow-hidden">
        <div className="flex flex-col items-center justify-center space-y-3.5">
          {/* Step 1: Requested Capability */}
          <div className="text-[10px] text-[#6F736A] uppercase tracking-widest font-semibold font-mono">
            Layer 3: Requested Tool Capability
          </div>
          <div className="bg-[#141713] border border-[#262C24] rounded-lg px-5 py-2.5 font-mono text-[#F0EEE5] font-bold shadow-sm z-10 w-72 text-center text-xs flex items-center justify-center gap-2">
            <Layers size={13} className="text-[#A2B89A]" />
            {scenario.capability}
          </div>
          
          <ArrowDown size={18} className="text-[#6F736A]" />
          
          {/* Step 2: Destination Binding Comparison */}
          <div className="text-[10px] text-[#6F736A] uppercase tracking-widest font-semibold font-mono">
            Layer 4: Destination Verification
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 w-full max-w-md z-10">
            <div className="flex flex-col items-center gap-1.5">
              <span className="text-[10px] text-[#6F736A] uppercase tracking-widest font-semibold font-mono">
                Requested Target
              </span>
              <div className={`border rounded-lg px-3 py-2 font-mono text-xs text-center w-full shadow-sm ${
                scenario.requestedDest !== scenario.expectedDest 
                  ? 'bg-[#C25D54]/10 border-[#C25D54]/30 text-[#C25D54] font-bold' 
                  : 'bg-[#141713] border-[#262C24] text-[#F0EEE5]'
              }`}>
                {scenario.requestedDest}
              </div>
            </div>
            
            <div className="flex flex-col items-center gap-1.5">
              <span className="text-[10px] text-[#6F736A] uppercase tracking-widest font-semibold font-mono">
                Policy Destination
              </span>
              <div className="bg-[#141713] border border-[#8FA887]/30 text-[#8FA887] rounded-lg px-3 py-2 font-mono text-xs text-center w-full shadow-sm font-bold">
                {scenario.expectedDest}
              </div>
            </div>
          </div>

          <div className="h-5 border-l border-dashed border-[#262C24] my-0.5"></div>
          
          {/* Step 3: Gateway Outcome */}
          {scenario.decision === "BLOCK" ? (
            <div className="bg-[#C25D54]/10 border border-[#C25D54]/30 rounded-xl p-4 flex flex-col items-center z-10 w-72 text-center space-y-1">
              <XCircle size={26} className="text-[#C25D54]" />
              <h3 className="text-[#C25D54] font-bold text-sm font-mono tracking-wide">GATEWAY BLOCKED</h3>
              <p className="text-[#C25D54]/80 text-[11px] font-mono">{scenario.reason}</p>
            </div>
          ) : (
            <div className="bg-[#8FA887]/10 border border-[#8FA887]/30 rounded-xl p-4 flex flex-col items-center z-10 w-72 text-center space-y-1">
              <CheckCircle2 size={26} className="text-[#8FA887]" />
              <h3 className="text-[#8FA887] font-bold text-sm font-mono tracking-wide">GATEWAY ALLOWED</h3>
              <p className="text-[#8FA887]/80 text-[11px] font-mono">{scenario.reason}</p>
            </div>
          )}
          
          <div className="h-5 border-l border-dashed border-[#262C24] my-0.5"></div>

          {/* Step 4: Downstream Execution Status */}
          <div className={`border rounded-lg px-5 py-2 font-mono text-xs font-bold shadow-sm z-10 flex items-center gap-2 ${
            scenario.downstream === 'NOT CONTACTED' 
              ? 'bg-[#141713] border-[#262C24] text-[#A5A69C]' 
              : 'bg-[#8FA887]/10 border-[#8FA887]/30 text-[#8FA887]'
          }`}>
            <Shield size={13} className={scenario.downstream === 'NOT CONTACTED' ? 'text-[#6F736A]' : 'text-[#8FA887]'} />
            DOWNSTREAM ADAPTER: {scenario.downstream}
          </div>

          {/* Explanation Text */}
          <div className="bg-[#141713] border border-[#262C24] rounded-lg p-3.5 text-xs text-[#A5A69C] text-center max-w-lg mt-3 leading-relaxed">
            {scenario.explanation}
          </div>
        </div>
      </div>
    </div>
  );
};
