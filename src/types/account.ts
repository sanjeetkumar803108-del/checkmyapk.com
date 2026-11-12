export type AccountPlan = 'free' | 'pro' | 'agency';

export interface SavedScanEntry {
  id: string;
  target: string;
  mode: 'apk' | 'web';
  score: number;
  grade: string;
  criticalCount: number;
  timestamp: string;
}

export interface TrackedTargetUsage {
  target: string;
  count: number;
}

export interface UserAccount {
  id: string;
  name: string;
  email: string;
  avatarUrl?: string;
  authProvider?: 'email' | 'google';
  plan: AccountPlan;
  dailyScansUsed: number;
  dailyScanLimit: number | null;
  scanQuotaPeriod?: 'month' | 'day';
  monthlyAppsUsed: number;
  monthlyAppLimit: number;
  maxApkMb: number;
  maxRescansPerTarget: number | null;
  monthlyTargets?: TrackedTargetUsage[];
  apiToken: string;
  scansHistory: SavedScanEntry[];
  createdAt: string;
}

