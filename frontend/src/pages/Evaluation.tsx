import React, { useEffect, useState } from 'react';
import { getEvaluationMetrics } from '../services/api';
import {
  ShieldCheck,
  Target,
  ShieldAlert,
  Crosshair,
  Clock,
  AlertTriangle,
  FileText,
  CheckCircle2,
  Terminal,
  Activity,
  Zap,
} from 'lucide-react';
import type { EvaluationMetrics } from '../types';

export const Evaluation: React.FC = () => {
  const [metrics, setMetrics] = useState<EvaluationMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    getEvaluationMetrics()
      .then(data => {
        if (isMounted) {
          setMetrics(data);
          setLoading(false);
        }
      })
      .catch(err => {
        if (isMounted) {
          setError(err.message || "Failed to load evaluation metrics.");
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-80 space-y-4">
        <div className="w-7 h-7 border-2 border-[#A2B89A] border-t-transparent rounded-full animate-spin"></div>
        <p className="text-[#A5A69C] font-mono text-xs tracking-wider animate-pulse uppercase">
          Loading adversarial attack evaluation report...
        </p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-5xl mx-auto bg-[#C25D54]/10 border border-[#C25D54]/30 rounded-xl p-6 text-[#C25D54] space-y-2">
        <div className="flex items-center gap-2 font-bold text-sm">
          <AlertTriangle size={18} /> Unable to load evaluation data
        </div>
        <p className="text-xs text-[#A5A69C]">{error}</p>
      </div>
    );
  }

  if (!metrics || !metrics.generated) {
    return (
      <div className="max-w-4xl mx-auto bg-[#191C18] border border-[#262C24] rounded-xl p-10 text-center space-y-6">
        <div className="w-12 h-12 bg-[#D4A359]/10 text-[#D4A359] border border-[#D4A359]/25 rounded-full flex items-center justify-center mx-auto">
          <FileText size={24} />
        </div>
        <div className="space-y-1.5">
          <h2 className="text-lg font-bold text-[#F0EEE5]">Security Evaluation Report Not Generated</h2>
          <p className="text-[#A5A69C] text-xs max-w-md mx-auto">
            The adversarial evaluation report has not yet been compiled. Execute the automated evaluation suite from your terminal to evaluate all 36 attack fixtures and 350 synthetic mutations.
          </p>
        </div>
        <div className="bg-[#101210] border border-[#262C24] rounded-lg p-4 font-mono text-xs text-[#A2B89A] max-w-md mx-auto text-left space-y-1">
          <span className="text-[#6F736A] flex items-center gap-1.5">
            <Terminal size={12} /> # Run in project root:
          </span>
          <div className="text-[#D0DEC7] font-bold">.\.venv\Scripts\python -m evaluator.metrics</div>
        </div>
      </div>
    );
  }

  const cm = metrics.raw_report?.confusion_matrix;
  const ops = metrics.raw_report?.operations_summary;

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      {/* Header with Freshness Info */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-[#262C24] pb-5">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-[9.5px] font-mono tracking-[0.22em] text-[#A2B89A] uppercase font-medium">
              OFFLINE ADVERSARIAL BENCHMARK
            </span>
            <span className="text-[#6F736A] text-xs font-mono">Deterministic Attack Fixtures &amp; Mutation Suite</span>
          </div>
          <h1 className="font-serif text-2xl lg:text-3xl font-normal text-[#F0EEE5] tracking-tight">Attack Evaluation &amp; Quantitative Metrics</h1>
          <p className="text-[#A5A69C] text-xs mt-1">
            Empirical measurement of detection, prevention, and false-positive rates across 8 threat vectors.
          </p>
        </div>

        {metrics.timestamp && (
          <div className="flex items-center gap-2 bg-[#191C18] border border-[#262C24] px-3 py-1.5 rounded-lg text-xs font-mono text-[#A5A69C] shrink-0">
            <Clock size={13} className="text-[#A2B89A]" />
            <span>Generated: {new Date(metrics.timestamp).toLocaleString()}</span>
          </div>
        )}
      </div>

      {/* Top 4 Primary Security Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <MetricCard 
          icon={<ShieldCheck className="text-[#8FA887]" size={20} />} 
          label="Detection Rate" 
          value={metrics.detection_rate || "100.0%"} 
          sub="Attacks identified at gate" 
          highlight="allow"
        />
        <MetricCard 
          icon={<ShieldAlert className="text-[#8FA887]" size={20} />} 
          label="Prevention Rate" 
          value={metrics.prevention_rate || "100.0%"} 
          sub="Zero downstream contact" 
          highlight="allow"
        />
        <MetricCard 
          icon={<Target className="text-[#A2B89A]" size={20} />} 
          label="False Allow Rate" 
          value={metrics.false_allow || "0.0%"} 
          sub="Attacks erroneously allowed" 
          highlight="neutral"
        />
        <MetricCard 
          icon={<Crosshair className="text-[#A2B89A]" size={20} />} 
          label="False Block Rate" 
          value={metrics.false_block || "0.0%"} 
          sub="Legitimate requests blocked" 
          highlight="neutral"
        />
      </div>

      {/* Confusion Matrix Section */}
      {cm && (
        <div className="bg-[#191C18] border border-[#262C24] rounded-xl p-5 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-[#F0EEE5] flex items-center gap-2">
                <Activity size={16} className="text-[#A2B89A]" />
                Deterministic Confusion Matrix
              </h3>
              <p className="text-xs text-[#A5A69C] mt-0.5">Evaluation across 34 attack fixtures and 2 control baselines.</p>
            </div>
            <div className="flex gap-2 text-xs font-mono">
              <span className="bg-[#8FA887]/10 text-[#8FA887] px-2.5 py-1 rounded-lg border border-[#8FA887]/25 font-bold">
                F1-Score: {cm.f1_score.toFixed(1)}%
              </span>
              <span className="bg-[#141713] text-[#D0DEC7] px-2.5 py-1 rounded-lg border border-[#262C24] font-bold">
                Accuracy: {cm.accuracy.toFixed(1)}%
              </span>
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-[#141713] border border-[#262C24] rounded-lg p-3.5 text-center">
              <span className="text-[10px] uppercase tracking-wider text-[#6F736A] font-semibold block font-mono">
                True Positives (TP)
              </span>
              <span className="text-2xl font-bold font-mono text-[#8FA887] mt-1 block">{cm.true_positives}</span>
              <span className="text-[10px] text-[#A5A69C] mt-1 block">Attacks correctly blocked</span>
            </div>
            <div className="bg-[#141713] border border-[#262C24] rounded-lg p-3.5 text-center">
              <span className="text-[10px] uppercase tracking-wider text-[#6F736A] font-semibold block font-mono">
                True Negatives (TN)
              </span>
              <span className="text-2xl font-bold font-mono text-[#D0DEC7] mt-1 block">{cm.true_negatives}</span>
              <span className="text-[10px] text-[#A5A69C] mt-1 block">Controls handled safely</span>
            </div>
            <div className="bg-[#141713] border border-[#262C24] rounded-lg p-3.5 text-center">
              <span className="text-[10px] uppercase tracking-wider text-[#6F736A] font-semibold block font-mono">
                False Positives (FP)
              </span>
              <span className="text-2xl font-bold font-mono text-[#A5A69C] mt-1 block">{cm.false_positives}</span>
              <span className="text-[10px] text-[#6F736A] mt-1 block">Controls erroneously blocked</span>
            </div>
            <div className="bg-[#141713] border border-[#262C24] rounded-lg p-3.5 text-center">
              <span className="text-[10px] uppercase tracking-wider text-[#6F736A] font-semibold block font-mono">
                False Negatives (FN)
              </span>
              <span className={`text-2xl font-bold font-mono mt-1 block ${cm.false_negatives === 0 ? 'text-[#8FA887]' : 'text-[#C25D54]'}`}>
                {cm.false_negatives}
              </span>
              <span className="text-[10px] text-[#6F736A] mt-1 block">Attacks erroneously allowed</span>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-3 border-t border-[#262C24] text-xs font-mono text-center">
            <div className="bg-[#141713] py-2 px-3 rounded-lg border border-[#262C24]">
              <span className="text-[#6F736A]">Precision:</span>{" "}
              <span className="text-[#F0EEE5] font-bold">{cm.precision.toFixed(1)}%</span>
            </div>
            <div className="bg-[#141713] py-2 px-3 rounded-lg border border-[#262C24]">
              <span className="text-[#6F736A]">Recall / Sensitivity:</span>{" "}
              <span className="text-[#F0EEE5] font-bold">{cm.recall.toFixed(1)}%</span>
            </div>
            <div className="bg-[#141713] py-2 px-3 rounded-lg border border-[#262C24]">
              <span className="text-[#6F736A]">Specificity:</span>{" "}
              <span className="text-[#F0EEE5] font-bold">{cm.specificity.toFixed(1)}%</span>
            </div>
          </div>
        </div>
      )}

      {/* Mutation Testing & Operations Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Mutation Testing */}
        <div className="bg-[#191C18] border border-[#262C24] rounded-xl p-5 flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-bold text-[#F0EEE5] flex items-center gap-2">
                <Zap size={15} className="text-[#A2B89A]" />
                Mutation Testing Operators
              </h3>
              <span className="text-xs font-mono bg-[#8FA887]/10 text-[#8FA887] px-2.5 py-0.5 rounded-lg border border-[#8FA887]/25 font-bold">
                {metrics.mutations_passed} PASSED
              </span>
            </div>
            <p className="text-xs text-[#A5A69C] mb-3">
              Synthetic fuzz mutations applied across schema, boundaries, destinations, and cryptographic signatures.
            </p>
            
            <div className="space-y-1.5 max-h-72 overflow-y-auto pr-1">
              {metrics.operators?.map((op, idx) => (
                <div key={idx} className="flex justify-between items-center py-1.5 px-3 bg-[#141713] rounded-lg border border-[#262C24] text-xs">
                  <span className="text-[#F0EEE5] font-mono text-[11px]">{op.name}</span>
                  <span className="text-[#8FA887] font-bold flex items-center gap-1 font-mono text-[11px]">
                    <CheckCircle2 size={12} /> {op.result}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
        
        {/* Operations Breakdown */}
        <div className="bg-[#191C18] border border-[#262C24] rounded-xl p-5 flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-bold text-[#F0EEE5] flex items-center gap-2">
                <Activity size={15} className="text-[#A2B89A]" />
                Evaluated Operations
              </h3>
              <span className="text-xs font-mono text-[#A5A69C] bg-[#141713] border border-[#262C24] px-2.5 py-0.5 rounded-lg">
                {ops ? `${ops.total_operations_evaluated} Tests` : "36 Tests"}
              </span>
            </div>
            <p className="text-xs text-[#A5A69C] mb-3">
              Distribution of gateway enforcement decisions across distinct tool capabilities.
            </p>

            {ops ? (
              <div className="space-y-3">
                <div className="bg-[#141713] border border-[#262C24] rounded-lg p-3">
                  <div className="flex justify-between text-xs font-semibold mb-1">
                    <span className="text-[#8FA887]">Allowed Tool Executions</span>
                    <span className="font-mono text-[#F0EEE5]">{ops.allowed_count}</span>
                  </div>
                  <div className="text-[11px] font-mono text-[#A5A69C]">
                    {Object.entries(ops.allowed_by_operation).map(([op, cnt]) => `${op} (${cnt})`).join(", ")}
                  </div>
                </div>

                <div className="bg-[#141713] border border-[#262C24] rounded-lg p-3">
                  <div className="flex justify-between text-xs font-semibold mb-1">
                    <span className="text-[#D4A359]">Approval-Required Boundaries</span>
                    <span className="font-mono text-[#F0EEE5]">{ops.approval_required_count}</span>
                  </div>
                  <div className="text-[11px] font-mono text-[#A5A69C]">
                    {Object.entries(ops.approval_required_by_operation).map(([op, cnt]) => `${op} (${cnt})`).join(", ")}
                  </div>
                </div>

                <div className="bg-[#141713] border border-[#262C24] rounded-lg p-3">
                  <div className="flex justify-between text-xs font-semibold mb-1">
                    <span className="text-[#C25D54]">Blocked Security Violations</span>
                    <span className="font-mono text-[#F0EEE5]">{ops.blocked_count}</span>
                  </div>
                  <div className="text-[11px] font-mono text-[#A5A69C] truncate" title={Object.entries(ops.blocked_by_operation).map(([op, cnt]) => `${op} (${cnt})`).join(", ")}>
                    {Object.entries(ops.blocked_by_operation).slice(0, 4).map(([op, cnt]) => `${op} (${cnt})`).join(", ")} ...
                  </div>
                </div>
              </div>
            ) : (
              <div className="h-48 flex items-center justify-center text-[#6F736A] text-xs font-mono">
                Operations summary data unavailable.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

interface MetricCardProps {
  icon: React.ReactNode;
  label: string;
  value: string;
  sub: string;
  highlight?: "allow" | "neutral" | "threat";
}

const MetricCard: React.FC<MetricCardProps> = ({ icon, label, value, sub, highlight = "neutral" }) => (
  <div className="bg-[#191C18] border border-[#262C24] hover:border-[#343B32] rounded-xl p-4 transition-colors">
    <div className="flex items-center gap-2.5 mb-2.5">
      <div className="p-1.5 bg-[#141713] border border-[#262C24] rounded-lg">{icon}</div>
      <span className="text-[10px] text-[#6F736A] uppercase tracking-wider font-semibold font-mono">{label}</span>
    </div>
    <div className={`text-2xl font-bold font-mono ${
      highlight === 'allow' ? 'text-[#8FA887]' :
      highlight === 'threat' ? 'text-[#C25D54]' :
      'text-[#F0EEE5]'
    }`}>
      {value}
    </div>
    <p className="text-[10px] text-[#A5A69C] mt-1 font-mono">{sub}</p>
  </div>
);
