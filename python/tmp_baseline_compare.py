import os
import re
import csv
import subprocess
import time
from statistics import median

LOSS = [0.1, 0.2, 0.3, 0.4, 0.5]
REPS = 3
BITRATE = 50
RTT = 20

RUN_RE = re.compile(r"\[run\].*loss=([0-9.]+)%.*dur_ms=([0-9]+).*md5_ok=([01]).*s_mbps=([0-9.]+)")


def run(script: str, loss: float) -> dict:
    env = os.environ.copy()
    env.update({"BITRATE_MBPS": str(BITRATE), "RTT_MS": str(RTT), "LOSS_PCT": str(loss)})
    p = subprocess.run(
        ["bash", "-lc", script],
        cwd=os.path.dirname(os.path.dirname(__file__)),
        env=env,
        text=True,
        capture_output=True,
        timeout=180,
    )
    out = (p.stdout or "") + "\n" + (p.stderr or "")
    m = RUN_RE.search(out)
    if not m:
        tail = "\n".join(out.splitlines()[-80:])
        raise RuntimeError(f"no [run] line in output for {script} loss={loss}\n---tail---\n{tail}")
    return {
        "loss_pct": float(m.group(1)),
        "dur_ms": int(m.group(2)),
        "md5_ok": int(m.group(3)),
        "goodput_mbps": float(m.group(4)),
    }


def main() -> int:
    rows = []
    for loss in LOSS:
        for rep in range(REPS):
            for script, label in [
                ("scripts/quicraw_run_once.sh", "quic_raw"),
                ("scripts/tcp_run_once.sh", "tcp"),
            ]:
                r = run(script, loss)
                r["rep"] = rep
                r["proto"] = label
                rows.append(r)
                print(
                    f"loss={loss:.1f}% rep={rep} proto={label} goodput={r['goodput_mbps']:.3f} md5_ok={r['md5_ok']} dur_ms={r['dur_ms']}"
                )
                time.sleep(0.1)

    out_path = os.path.join(os.path.dirname(__file__), "results", "baseline_quicraw_tcp_bw50_loss_0p1_0p5_reps3.csv")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["proto", "loss_pct", "rep", "goodput_mbps", "dur_ms", "md5_ok"])
        w.writeheader()
        for r in rows:
            w.writerow({k: r[k] for k in w.fieldnames})

    print("\nSummary (median goodput over md5_ok=1 reps):")
    for proto in ("quic_raw", "tcp"):
        for loss in LOSS:
            vals = [
                r["goodput_mbps"]
                for r in rows
                if r["proto"] == proto and abs(r["loss_pct"] - loss) < 1e-9 and r["md5_ok"] == 1
            ]
            print(f"{proto:8s} loss={loss:.1f}% median={median(vals):.3f} ok={len(vals)}/{REPS}")

    print("\nCSV:", out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
