import BarField3D from "./BarField3D";
import { SEV_HEX } from "./ccConstants";

const ROWS = ["critical", "high", "medium", "low"].map((sev) => ({ key: sev, label: sev, color: SEV_HEX[sev] }));

/** 3D terrain of new findings: one column per time bucket, one row per severity. */
export default function RiskTerrain({ labels = [], detection = {}, bucket = "week" }) {
  return (
    <BarField3D
      rows={ROWS}
      cols={labels}
      values={ROWS.map((r) => detection[r.key] || [])}
      caption={`New findings per ${bucket}, by severity`}
      describe={(row, col, value) => <><strong>{value}</strong> {row.label} found in the {bucket} of {col}</>}
      footer={
        <div className="an-terrain__axis cc-mono">
          <span>{labels[0]}</span>
          <span>← {bucket}s →</span>
          <span>{labels[labels.length - 1]}</span>
        </div>
      }
    />
  );
}
