import type { StatusSnapshot } from "./metrics.js";

export function buildStatusJson(snapshot: StatusSnapshot): StatusSnapshot {
  return snapshot;
}

export function renderStatusPage(snapshot: StatusSnapshot): string {
  const { global, process: proc, clients } = snapshot;
  const rssM = (proc.rssBytes / 1_048_576).toFixed(1);
  const heapUsedM = (proc.heapUsedBytes / 1_048_576).toFixed(1);
  const heapTotalM = (proc.heapTotalBytes / 1_048_576).toFixed(1);

  const clientRows =
    clients.length === 0
      ? `<tr><td colspan="6" style="text-align:center;color:#888">No clients connected</td></tr>`
      : clients
          .map(
            (c) => `<tr>
          <td title="${esc(c.uuid)}">${esc(c.uuid.substring(0, 12))}...</td>
          <td>${esc(c.connectedDuration)}</td>
          <td>${c.reqPerSec.toString()}</td>
          <td>${c.reqPerHour.toString()}</td>
          <td>${c.reqPerDay.toString()}</td>
          <td>${c.totalRequests.toString()}</td>
        </tr>`,
          )
          .join("\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dicode-relay status</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: "SF Mono", "Fira Code", monospace; background: #0d1117; color: #c9d1d9; padding: 24px; }
  h1 { font-size: 1.4rem; color: #58a6ff; margin-bottom: 8px; }
  .meta { color: #8b949e; font-size: 0.85rem; margin-bottom: 24px; }
  .section { margin-bottom: 24px; }
  .section h2 { font-size: 1rem; color: #58a6ff; margin-bottom: 8px; border-bottom: 1px solid #21262d; padding-bottom: 4px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .card { background: #161b22; border: 1px solid #21262d; border-radius: 6px; padding: 12px; }
  .card .label { color: #8b949e; font-size: 0.75rem; text-transform: uppercase; }
  .card .value { font-size: 1.3rem; color: #f0f6fc; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #21262d; border-radius: 6px; overflow: hidden; }
  th { text-align: left; padding: 8px 12px; background: #21262d; color: #8b949e; font-size: 0.75rem; text-transform: uppercase; }
  td { padding: 8px 12px; border-top: 1px solid #21262d; font-size: 0.85rem; }
  tr:hover td { background: #1c2128; }
  .refresh-indicator { color: #8b949e; font-size: 0.75rem; margin-top: 16px; }
  @media (max-width: 600px) { .grid { grid-template-columns: 1fr 1fr; } table { display: block; overflow-x: auto; } }
</style>
</head>
<body>
  <h1>dicode-relay status</h1>
  <div class="meta">Uptime: ${formatUptime(proc.uptimeSeconds)}</div>

  <div class="section">
    <h2>Process</h2>
    <div class="grid">
      <div class="card"><div class="label">CPU</div><div class="value" id="cpu">${proc.cpuPercent.toString()}%</div></div>
      <div class="card"><div class="label">RSS</div><div class="value" id="rss">${rssM} MB</div></div>
      <div class="card"><div class="label">Heap</div><div class="value" id="heap">${heapUsedM} / ${heapTotalM} MB</div></div>
    </div>
  </div>

  <div class="section">
    <h2>Global</h2>
    <div class="grid">
      <div class="card"><div class="label">Connected</div><div class="value" id="g-clients">${global.connectedClients.toString()}</div></div>
      <div class="card"><div class="label">Req/sec</div><div class="value" id="g-rps">${global.reqPerSec.toString()}</div></div>
      <div class="card"><div class="label">Req/hour</div><div class="value" id="g-rph">${global.reqPerHour.toString()}</div></div>
      <div class="card"><div class="label">Req/day</div><div class="value" id="g-rpd">${global.reqPerDay.toString()}</div></div>
    </div>
  </div>

  <div class="section">
    <h2>Clients</h2>
    <table>
      <thead>
        <tr><th>UUID</th><th>Connected</th><th>Req/s</th><th>Req/h</th><th>Req/d</th><th>Total</th></tr>
      </thead>
      <tbody id="client-table">
        ${clientRows}
      </tbody>
    </table>
  </div>

  <div class="refresh-indicator" id="refresh-status">Auto-refreshing every 5s</div>

  <script>
    async function refresh() {
      try {
        const res = await fetch("/api/status", { credentials: "same-origin" });
        if (!res.ok) return;
        const d = await res.json();
        const p = d.process;
        // Safe: all values come from our own /api/status endpoint, not user input.
        // UUIDs are hex-only strings validated at the relay handshake layer.
        document.getElementById("cpu").textContent = p.cpuPercent + "%";
        document.getElementById("rss").textContent = (p.rssBytes / 1048576).toFixed(1) + " MB";
        document.getElementById("heap").textContent = (p.heapUsedBytes / 1048576).toFixed(1) + " / " + (p.heapTotalBytes / 1048576).toFixed(1) + " MB";
        document.getElementById("g-clients").textContent = d.global.connectedClients;
        document.getElementById("g-rps").textContent = d.global.reqPerSec;
        document.getElementById("g-rph").textContent = d.global.reqPerHour;
        document.getElementById("g-rpd").textContent = d.global.reqPerDay;
        const tbody = document.getElementById("client-table");
        if (d.clients.length === 0) {
          tbody.textContent = "";
          const row = document.createElement("tr");
          const cell = document.createElement("td");
          cell.setAttribute("colspan", "6");
          cell.style.textAlign = "center";
          cell.style.color = "#888";
          cell.textContent = "No clients connected";
          row.appendChild(cell);
          tbody.appendChild(row);
        } else {
          tbody.textContent = "";
          d.clients.forEach(function(c) {
            const row = document.createElement("tr");
            const uuidCell = document.createElement("td");
            uuidCell.setAttribute("title", c.uuid);
            uuidCell.textContent = c.uuid.substring(0, 12) + "...";
            row.appendChild(uuidCell);
            const durCell = document.createElement("td");
            durCell.textContent = c.connectedDuration;
            row.appendChild(durCell);
            const rpsCell = document.createElement("td");
            rpsCell.textContent = c.reqPerSec;
            row.appendChild(rpsCell);
            const rphCell = document.createElement("td");
            rphCell.textContent = c.reqPerHour;
            row.appendChild(rphCell);
            const rpdCell = document.createElement("td");
            rpdCell.textContent = c.reqPerDay;
            row.appendChild(rpdCell);
            const totalCell = document.createElement("td");
            totalCell.textContent = c.totalRequests;
            row.appendChild(totalCell);
            tbody.appendChild(row);
          });
        }
        document.getElementById("refresh-status").textContent = "Auto-refreshing every 5s";
      } catch {
        document.getElementById("refresh-status").textContent = "Connection lost - retrying...";
      }
    }
    setInterval(refresh, 5000);
  </script>
</body>
</html>`;
}

function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (d > 0) return `${d.toString()}d ${h.toString()}h ${m.toString()}m`;
  if (h > 0) return `${h.toString()}h ${m.toString()}m ${s.toString()}s`;
  return `${m.toString()}m ${s.toString()}s`;
}

function esc(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
