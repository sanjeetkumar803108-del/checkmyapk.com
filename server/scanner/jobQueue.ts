import crypto from 'crypto';

export type ScanJobStatus = 'queued' | 'running' | 'completed' | 'failed';

export interface ScanJobLog {
  time: string;
  msg: string;
}

export interface ScanJob {
  id: string;
  kind: 'apk' | 'web';
  targetName: string;
  status: ScanJobStatus;
  progress: number;
  currentStage: string;
  logs: ScanJobLog[];
  createdAt: number;
  updatedAt: number;
  result?: any;
  error?: string;
}

const JOB_TTL_MS = 30 * 60 * 1000;
const jobs = new Map<string, ScanJob>();

function pruneExpiredJobs() {
  const now = Date.now();
  for (const [id, job] of jobs.entries()) {
    if (now - job.updatedAt > JOB_TTL_MS && (job.status === 'completed' || job.status === 'failed')) {
      jobs.delete(id);
    }
  }
}

export function createScanJob(kind: 'apk' | 'web', targetName: string): ScanJob {
  pruneExpiredJobs();
  const id = `job_${crypto.randomBytes(8).toString('hex')}`;
  const now = Date.now();
  const job: ScanJob = {
    id,
    kind,
    targetName,
    status: 'queued',
    progress: 5,
    currentStage: 'Queued in CheckMyAPK async worker pipeline...',
    logs: [{ time: '[+0.00s]', msg: `Job ${id} queued for ${targetName}` }],
    createdAt: now,
    updatedAt: now
  };
  jobs.set(id, job);
  return job;
}

export function getScanJob(id: string): ScanJob | undefined {
  return jobs.get(id);
}

export function pushScanJobProgress(id: string, progress: number, stage: string, timeLabel?: string) {
  const job = jobs.get(id);
  if (!job) return;
  job.status = 'running';
  job.progress = Math.min(99, Math.max(job.progress, progress));
  job.currentStage = stage;
  const elapsed = ((Date.now() - job.createdAt) / 1000).toFixed(2);
  job.logs.push({ time: timeLabel || `[+${elapsed}s]`, msg: stage });
  job.updatedAt = Date.now();
}

export function completeScanJob(id: string, result: any) {
  const job = jobs.get(id);
  if (!job) return;
  job.status = 'completed';
  job.progress = 100;
  job.currentStage = 'Audit completed cleanly.';
  job.result = result;
  job.updatedAt = Date.now();
}

export function failScanJob(id: string, errorMessage: string) {
  const job = jobs.get(id);
  if (!job) return;
  job.status = 'failed';
  job.currentStage = 'Audit failed.';
  job.error = errorMessage;
  job.updatedAt = Date.now();
}

