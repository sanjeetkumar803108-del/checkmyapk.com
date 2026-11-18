import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

export type ScanModeKind = 'apk' | 'web';

export interface LiveScanStats {
  totalScans: number;
  apkScans: number;
  webScans: number;
  lastScanAt: string | null;
  lastScanMode: ScanModeKind | null;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.resolve(__dirname, '..', '..', '.data');
const STATS_PATH = path.join(DATA_DIR, 'scan_stats.json');
const ACCOUNTS_PATH = path.join(DATA_DIR, 'accounts.json');
const GUEST_QUOTAS_PATH = path.join(DATA_DIR, 'guest_quotas.json');

type StatsListener = (stats: LiveScanStats) => void;
const listeners = new Set<StatsListener>();

let cachedStats: LiveScanStats | null = null;

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function readJsonSafe<T>(filePath: string): T | null {
  try {
    if (!fs.existsSync(filePath)) return null;
    return JSON.parse(fs.readFileSync(filePath, 'utf8')) as T;
  } catch {
    return null;
  }
}

/**
 * Computes an initial 100% real scan baseline strictly from persisted local
 * scan records (accounts.json & guest_quotas.json) when scan_stats.json does
 * not exist yet. Never fabricates or inflates numbers.
 */
function computeRealHistoricalBaseline(): LiveScanStats {
  let apkScans = 0;
  let webScans = 0;
  let lastScanAt: string | null = null;
  let lastScanMode: ScanModeKind | null = null;

  const accountsDb = readJsonSafe<{
    users?: Array<{
      scansHistory?: Array<{ mode?: string; timestamp?: string }>;
      monthlyTargetCounts?: Record<string, number>;
    }>;
  }>(ACCOUNTS_PATH);

  if (Array.isArray(accountsDb?.users)) {
    for (const user of accountsDb.users) {
      let histApk = 0;
      let histWeb = 0;
      if (Array.isArray(user.scansHistory)) {
        for (const entry of user.scansHistory) {
          if (entry?.mode === 'apk') histApk += 1;
          else if (entry?.mode === 'web') histWeb += 1;

          if (typeof entry?.timestamp === 'string' && entry.timestamp) {
            if (!lastScanAt || Date.parse(entry.timestamp) > Date.parse(lastScanAt)) {
              lastScanAt = entry.timestamp;
              lastScanMode = entry.mode === 'apk' ? 'apk' : entry.mode === 'web' ? 'web' : lastScanMode;
            }
          }
        }
      }

      let targetApk = 0;
      let targetWeb = 0;
      if (user.monthlyTargetCounts && typeof user.monthlyTargetCounts === 'object') {
        for (const [key, count] of Object.entries(user.monthlyTargetCounts)) {
          const n = typeof count === 'number' && Number.isFinite(count) && count > 0 ? Math.floor(count) : 0;
          if (key.startsWith('apk:')) targetApk += n;
          else if (key.startsWith('web:')) targetWeb += n;
        }
      }

      apkScans += Math.max(histApk, targetApk);
      webScans += Math.max(histWeb, targetWeb);
    }
  }

  const guestDb = readJsonSafe<{
    guests?: Record<
      string,
      {
        monthlyTargetCounts?: Record<string, number>;
      }
    >;
  }>(GUEST_QUOTAS_PATH);

  if (guestDb?.guests && typeof guestDb.guests === 'object') {
    for (const guest of Object.values(guestDb.guests)) {
      if (guest?.monthlyTargetCounts && typeof guest.monthlyTargetCounts === 'object') {
        for (const [key, count] of Object.entries(guest.monthlyTargetCounts)) {
          const n = typeof count === 'number' && Number.isFinite(count) && count > 0 ? Math.floor(count) : 0;
          if (key.startsWith('apk:')) apkScans += n;
          else if (key.startsWith('web:')) webScans += n;
        }
      }
    }
  }

  return {
    totalScans: apkScans + webScans,
    apkScans,
    webScans,
    lastScanAt,
    lastScanMode,
  };
}

function saveStatsToDisk(stats: LiveScanStats) {
  try {
    ensureDataDir();
    const tmpPath = `${STATS_PATH}.tmp`;
    fs.writeFileSync(tmpPath, JSON.stringify(stats, null, 2), 'utf8');
    fs.renameSync(tmpPath, STATS_PATH);
  } catch (err) {
    console.warn('[ScanStats] Failed to persist scan_stats.json:', err);
  }
}

function loadStats(): LiveScanStats {
  if (cachedStats) return cachedStats;

  const existing = readJsonSafe<Partial<LiveScanStats>>(STATS_PATH);
  if (
    existing &&
    typeof existing.apkScans === 'number' &&
    typeof existing.webScans === 'number' &&
    Number.isFinite(existing.apkScans) &&
    Number.isFinite(existing.webScans)
  ) {
    const apkScans = Math.max(0, Math.floor(existing.apkScans));
    const webScans = Math.max(0, Math.floor(existing.webScans));
    cachedStats = {
      totalScans: apkScans + webScans,
      apkScans,
      webScans,
      lastScanAt: typeof existing.lastScanAt === 'string' ? existing.lastScanAt : null,
      lastScanMode:
        existing.lastScanMode === 'apk' || existing.lastScanMode === 'web'
          ? existing.lastScanMode
          : null,
    };
    return cachedStats;
  }

  cachedStats = computeRealHistoricalBaseline();
  saveStatsToDisk(cachedStats);
  return cachedStats;
}

export function getLiveScanStats(): LiveScanStats {
  return { ...loadStats() };
}

export function recordCompletedScan(mode: ScanModeKind): LiveScanStats {
  const current = loadStats();
  const next: LiveScanStats = {
    apkScans: current.apkScans + (mode === 'apk' ? 1 : 0),
    webScans: current.webScans + (mode === 'web' ? 1 : 0),
    totalScans: current.apkScans + current.webScans + 1,
    lastScanAt: new Date().toISOString(),
    lastScanMode: mode,
  };

  cachedStats = next;
  saveStatsToDisk(next);

  const snapshot = { ...next };
  for (const listener of listeners) {
    try {
      listener(snapshot);
    } catch {
      // Ignore individual broken stream listeners
    }
  }

  return snapshot;
}

export function subscribeScanStats(listener: StatsListener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}
