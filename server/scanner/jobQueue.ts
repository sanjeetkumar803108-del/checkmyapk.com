import crypto from 'crypto';
import { EventEmitter } from 'events';

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
  queuePosition: number;
  logs: ScanJobLog[];
  createdAt: number;
  updatedAt: number;
  result?: any;
  error?: string;
}

const JOB_TTL_MS = 30 * 60 * 1000;
const MAX_STORED_JOBS = 30;
const MAX_CONCURRENT_APK_JOBS = Number(process.env.MAX_CONCURRENT_APK_JOBS || 2);
const MAX_QUEUED_APK_JOBS = Number(process.env.MAX_QUEUED_APK_JOBS || 10);

const jobs = new Map<string, ScanJob>();
const jobEvents = new EventEmitter();
jobEvents.setMaxListeners(100);

interface QueuedTask {
  jobId: string;
  run: () => Promise<void>;
}

const pendingQueue: QueuedTask[] = [];
let activeWorkers = 0;

function pruneJobs() {
  const now = Date.now();
  for (const [id, job] of jobs.entries()) {
    if (now - job.updatedAt > JOB_TTL_MS && (job.status === 'completed' || job.status === 'failed')) {
      jobs.delete(id);
    }
  }
  while (jobs.size > MAX_STORED_JOBS) {
    let evicted = false;
    for (const [id, job] of jobs.entries()) {
      if (job.status === 'completed' || job.status === 'failed') {
        jobs.delete(id);
        evicted = true;
        break;
      }
    }
    if (!evicted) break;
  }
}

function updateQueuePositions() {
  pendingQueue.forEach((item, index) => {
    const job = jobs.get(item.jobId);
    if (job && job.status === 'queued') {
      job.queuePosition = index + 1;
      job.currentStage = `Queued behind active scans (position #${index + 1})...`;
      jobEvents.emit(item.jobId, job);
    }
  });
}

function drainQueue() {
  while (activeWorkers < MAX_CONCURRENT_APK_JOBS && pendingQueue.length > 0) {
    const next = pendingQueue.shift()!;
    updateQueuePositions();

    const job = jobs.get(next.jobId);
    if (job) {
      job.queuePosition = 0;
      job.status = 'running';
      jobEvents.emit(next.jobId, job);
    }

    activeWorkers++;
    Promise.resolve()
      .then(() => next.run())
      .catch(() => {})
      .finally(() => {
        activeWorkers = Math.max(0, activeWorkers - 1);
        drainQueue();
      });
  }
}

export function getQueueCapacity(): { activeWorkers: number; queuedCount: number; maxConcurrent: number; isFull: boolean } {
  return {
    activeWorkers,
    queuedCount: pendingQueue.length,
    maxConcurrent: MAX_CONCURRENT_APK_JOBS,
    isFull: activeWorkers >= MAX_CONCURRENT_APK_JOBS && pendingQueue.length >= MAX_QUEUED_APK_JOBS
  };
}

export function createScanJob(kind: 'apk' | 'web', targetName: string): ScanJob {
  pruneJobs();
  const id = `job_${crypto.randomBytes(8).toString('hex')}`;
  const now = Date.now();
  const pos = activeWorkers >= MAX_CONCURRENT_APK_JOBS ? pendingQueue.length + 1 : 0;
  const job: ScanJob = {
    id,
    kind,
    targetName,
    status: 'queued',
    progress: 5,
    currentStage: pos > 0 ? `Queued in worker pool (position #${pos})...` : 'Queued in CheckMyAPK async worker pipeline...',
    queuePosition: pos,
    logs: [{ time: '[+0.00s]', msg: `Job ${id} queued for ${targetName}` }],
    createdAt: now,
    updatedAt: now
  };
  jobs.set(id, job);
  return job;
}

export function enqueueJobTask(jobId: string, taskFn: () => Promise<void>): boolean {
  if (activeWorkers >= MAX_CONCURRENT_APK_JOBS && pendingQueue.length >= MAX_QUEUED_APK_JOBS) {
    return false;
  }
  pendingQueue.push({ jobId, run: taskFn });
  drainQueue();
  return true;
}

export function getScanJob(id: string): ScanJob | undefined {
  return jobs.get(id);
}

export function subscribeScanJob(id: string, listener: (job: ScanJob) => void): () => void {
  jobEvents.on(id, listener);
  return () => {
    jobEvents.off(id, listener);
  };
}

export function pushScanJobProgress(id: string, progress: number, stage: string, timeLabel?: string) {
  const job = jobs.get(id);
  if (!job) return;
  job.status = 'running';
  job.queuePosition = 0;
  job.progress = Math.min(99, Math.max(job.progress, progress));
  job.currentStage = stage;
  const elapsed = ((Date.now() - job.createdAt) / 1000).toFixed(2);
  job.logs.push({ time: timeLabel || `[+${elapsed}s]`, msg: stage });
  job.updatedAt = Date.now();
  jobEvents.emit(id, job);
}

export function completeScanJob(id: string, result: any) {
  const job = jobs.get(id);
  if (!job) return;
  job.status = 'completed';
  job.queuePosition = 0;
  job.progress = 100;
  job.currentStage = 'Audit completed cleanly.';
  job.result = result;
  job.updatedAt = Date.now();
  jobEvents.emit(id, job);
}

export function failScanJob(id: string, errorMessage: string) {
  const job = jobs.get(id);
  if (!job) return;
  job.status = 'failed';
  job.queuePosition = 0;
  job.currentStage = 'Audit failed.';
  job.error = errorMessage;
  job.updatedAt = Date.now();
  jobEvents.emit(id, job);
}
