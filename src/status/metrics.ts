const SECONDS_PER_HOUR = 3600;
const HOURS_PER_DAY = 24;

interface ClientMetricsEntry {
  uuid: string;
  connectedAt: number;
  secondBuckets: Uint32Array;
  secondIndex: number;
  secondEpoch: number;
  hourBuckets: Uint32Array;
  hourIndex: number;
  hourEpoch: number;
  totalRequests: number;
}

export interface ClientSnapshot {
  uuid: string;
  connectedAt: number;
  connectedDuration: string;
  reqPerSec: number;
  reqPerHour: number;
  reqPerDay: number;
  totalRequests: number;
}

export interface ProcessSnapshot {
  uptimeSeconds: number;
  rssBytes: number;
  heapUsedBytes: number;
  heapTotalBytes: number;
  cpuPercent: number;
}

export interface StatusSnapshot {
  global: {
    connectedClients: number;
    reqPerSec: number;
    reqPerHour: number;
    reqPerDay: number;
  };
  process: ProcessSnapshot;
  clients: ClientSnapshot[];
}

export class MetricsCollector {
  private readonly entries = new Map<string, ClientMetricsEntry>();
  private lastCpuUsage = process.cpuUsage();
  private lastCpuTime = Date.now();
  private cachedCpuPercent = 0;

  registerClient(uuid: string): void {
    const nowSec = Math.floor(Date.now() / 1000);
    const nowHour = Math.floor(nowSec / 3600);
    this.entries.set(uuid, {
      uuid,
      connectedAt: Date.now(),
      secondBuckets: new Uint32Array(SECONDS_PER_HOUR),
      secondIndex: 0,
      secondEpoch: nowSec,
      hourBuckets: new Uint32Array(HOURS_PER_DAY),
      hourIndex: 0,
      hourEpoch: nowHour,
      totalRequests: 0,
    });
  }

  removeClient(uuid: string): void {
    this.entries.delete(uuid);
  }

  record(uuid: string): void {
    const entry = this.entries.get(uuid);
    if (entry === undefined) return;

    const nowSec = Math.floor(Date.now() / 1000);
    const nowHour = Math.floor(nowSec / 3600);

    this.advanceSecondBuckets(entry, nowSec);
    this.advanceHourBuckets(entry, nowHour);

    const si = entry.secondIndex;
    const hi = entry.hourIndex;
    entry.secondBuckets[si] = (entry.secondBuckets[si] ?? 0) + 1;
    entry.hourBuckets[hi] = (entry.hourBuckets[hi] ?? 0) + 1;
    entry.totalRequests++;
  }

  snapshot(): StatusSnapshot {
    const now = Date.now();
    const nowSec = Math.floor(now / 1000);
    const nowHour = Math.floor(nowSec / 3600);
    const clients: ClientSnapshot[] = [];

    let globalReqPerSec = 0;
    let globalReqPerHour = 0;
    let globalReqPerDay = 0;

    for (const entry of this.entries.values()) {
      this.advanceSecondBuckets(entry, nowSec);
      this.advanceHourBuckets(entry, nowHour);

      const reqPerSec = entry.secondBuckets[entry.secondIndex] ?? 0;
      const reqPerHour = sumUint32Array(entry.secondBuckets);
      const reqPerDay = sumUint32Array(entry.hourBuckets);

      globalReqPerSec += reqPerSec;
      globalReqPerHour += reqPerHour;
      globalReqPerDay += reqPerDay;

      clients.push({
        uuid: entry.uuid,
        connectedAt: entry.connectedAt,
        connectedDuration: formatDuration(now - entry.connectedAt),
        reqPerSec,
        reqPerHour,
        reqPerDay,
        totalRequests: entry.totalRequests,
      });
    }

    clients.sort((a, b) => b.totalRequests - a.totalRequests);

    return {
      global: {
        connectedClients: this.entries.size,
        reqPerSec: globalReqPerSec,
        reqPerHour: globalReqPerHour,
        reqPerDay: globalReqPerDay,
      },
      process: this.processSnapshot(),
      clients,
    };
  }

  private advanceSecondBuckets(entry: ClientMetricsEntry, nowSec: number): void {
    const elapsed = nowSec - entry.secondEpoch;
    if (elapsed <= 0) return;

    const toZero = Math.min(elapsed, SECONDS_PER_HOUR);
    for (let i = 1; i <= toZero; i++) {
      const idx = (entry.secondIndex + i) % SECONDS_PER_HOUR;
      entry.secondBuckets[idx] = 0;
    }
    entry.secondIndex = (entry.secondIndex + elapsed) % SECONDS_PER_HOUR;
    entry.secondEpoch = nowSec;
  }

  private advanceHourBuckets(entry: ClientMetricsEntry, nowHour: number): void {
    const elapsed = nowHour - entry.hourEpoch;
    if (elapsed <= 0) return;

    const toZero = Math.min(elapsed, HOURS_PER_DAY);
    for (let i = 1; i <= toZero; i++) {
      const idx = (entry.hourIndex + i) % HOURS_PER_DAY;
      entry.hourBuckets[idx] = 0;
    }
    entry.hourIndex = (entry.hourIndex + elapsed) % HOURS_PER_DAY;
    entry.hourEpoch = nowHour;
  }

  private processSnapshot(): ProcessSnapshot {
    const now = Date.now();
    const elapsedMs = now - this.lastCpuTime;

    if (elapsedMs >= 1000) {
      const currentCpu = process.cpuUsage(this.lastCpuUsage);
      const totalCpuUs = currentCpu.user + currentCpu.system;
      this.cachedCpuPercent = (totalCpuUs / (elapsedMs * 1000)) * 100;
      this.lastCpuUsage = process.cpuUsage();
      this.lastCpuTime = now;
    }

    const mem = process.memoryUsage();
    return {
      uptimeSeconds: Math.floor(process.uptime()),
      rssBytes: mem.rss,
      heapUsedBytes: mem.heapUsed,
      heapTotalBytes: mem.heapTotal,
      cpuPercent: Math.round(this.cachedCpuPercent * 100) / 100,
    };
  }
}

function sumUint32Array(arr: Uint32Array): number {
  let sum = 0;
  for (const val of arr) {
    sum += val;
  }
  return sum;
}

function formatDuration(ms: number): string {
  const totalSeconds = Math.floor(ms / 1000);
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  if (days > 0) return `${days.toString()}d ${hours.toString()}h ${minutes.toString()}m`;
  if (hours > 0) return `${hours.toString()}h ${minutes.toString()}m`;
  if (minutes > 0) return `${minutes.toString()}m ${seconds.toString()}s`;
  return `${seconds.toString()}s`;
}
