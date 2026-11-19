import axios from 'axios';
import { AUDIT_HTTPS_AGENT, validateTargetSafety } from './securityGuard.ts';

export interface CloudBucketProbeSummary {
  provider: 'AWS S3' | 'Google Cloud Storage' | 'Azure Blob Storage';
  bucketUrl: string;
  listUrl: string;
  status: number | string;
  publicListable: boolean;
  sampleKeys: string[];
}

export interface CloudBucketFinding {
  category: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'PASS';
  proof: string;
  description: string;
  remediation: string;
  owaspRef: string;
}

export interface CloudBucketAuditResult {
  findings: CloudBucketFinding[];
  probedBuckets: CloudBucketProbeSummary[];
}

const SKIP_BUCKETS = new Set([
  'fonts.googleapis.com',
  'storage.googleapis.com/chromium-browser-snapshots',
  'storage.googleapis.com/flutter_infra_release',
  'storage.googleapis.com/gweb-uniblog-publish-prod',
]);

function extractCandidateBuckets(
  texts: string[]
): Array<{ provider: CloudBucketProbeSummary['provider']; bucketUrl: string; listUrl: string }> {
  const combined = texts.join('\n');
  const seen = new Set<string>();
  const out: Array<{ provider: CloudBucketProbeSummary['provider']; bucketUrl: string; listUrl: string }> = [];

  const addBucket = (
    provider: CloudBucketProbeSummary['provider'],
    bucketUrl: string,
    listUrl: string
  ) => {
    const clean = bucketUrl.replace(/\/+$/, '');
    if (seen.has(clean) || SKIP_BUCKETS.has(clean.replace(/^https?:\/\//, ''))) return;
    seen.add(clean);
    out.push({ provider, bucketUrl: clean, listUrl });
  };

  // 1. AWS S3 virtual-hosted-style: https://my-bucket.s3.amazonaws.com or my-bucket.s3.us-east-1.amazonaws.com
  const s3VirtualRe = /https?:\/\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3(?:\.[a-z0-9-]+)?\.amazonaws\.com\b/gi;
  for (const m of combined.matchAll(s3VirtualRe)) {
    const hostUrl = m[0].replace(/^http:\/\//i, 'https://');
    addBucket('AWS S3', hostUrl, `${hostUrl}/?list-type=2&max-keys=5`);
  }

  // 2. AWS S3 path-style: https://s3.amazonaws.com/my-bucket or https://s3.us-east-1.amazonaws.com/my-bucket
  const s3PathRe = /https?:\/\/s3(?:\.[a-z0-9-]+)?\.amazonaws\.com\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\b/gi;
  for (const m of combined.matchAll(s3PathRe)) {
    const bucketUrl = m[0].replace(/^http:\/\//i, 'https://');
    addBucket('AWS S3', bucketUrl, `${bucketUrl}?list-type=2&max-keys=5`);
  }

  // 3. Google Cloud Storage: https://storage.googleapis.com/<bucket>
  const gcsRe = /https?:\/\/storage\.googleapis\.com\/([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])\b/gi;
  for (const m of combined.matchAll(gcsRe)) {
    const bucket = m[1];
    if (!bucket || bucket === 'storage' || bucket === 'download') continue;
    const base = `https://storage.googleapis.com/${bucket}`;
    addBucket(
      'Google Cloud Storage',
      base,
      `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(bucket)}/o?maxResults=5`
    );
  }

  // 4. Azure Blob Storage: https://<account>.blob.core.windows.net/<container>
  const azureRe = /https?:\/\/([a-z0-9]{3,24})\.blob\.core\.windows\.net\/([a-z0-9-]{3,63})\b/gi;
  for (const m of combined.matchAll(azureRe)) {
    const base = `https://${m[1].toLowerCase()}.blob.core.windows.net/${m[2].toLowerCase()}`;
    addBucket('Azure Blob Storage', base, `${base}?restype=container&comp=list&maxresults=5`);
  }

  return out.slice(0, 3);
}

export async function auditCloudStorageBuckets(
  texts: string[],
  options: { isProd: boolean; isApk?: boolean }
): Promise<CloudBucketAuditResult> {
  const candidates = extractCandidateBuckets(texts);
  if (candidates.length === 0) {
    return { findings: [], probedBuckets: [] };
  }

  const findings: CloudBucketFinding[] = [];
  const probedBuckets: CloudBucketProbeSummary[] = [];
  const owaspRef = options.isApk ? 'MASVS-STORAGE-1' : 'OWASP-A01';

  await Promise.all(
    candidates.map(async (c) => {
      try {
        const safety = await validateTargetSafety(c.listUrl, { isProd: options.isProd });
        if (!safety.allowed) {
          probedBuckets.push({
            provider: c.provider,
            bucketUrl: c.bucketUrl,
            listUrl: c.listUrl,
            status: 'Blocked',
            publicListable: false,
            sampleKeys: [],
          });
          return;
        }

        const res = await axios.get(c.listUrl, {
          timeout: 2600,
          httpsAgent: AUDIT_HTTPS_AGENT,
          maxContentLength: 256 * 1024,
          maxRedirects: 1,
          validateStatus: () => true,
          headers: { 'User-Agent': 'CheckMyAPK-Auditor/1.0 (+https://checkmyapk.com)' },
        });

        let publicListable = false;
        const sampleKeys: string[] = [];

        if (res.status === 200) {
          if (typeof res.data === 'string') {
            if (res.data.includes('<ListBucketResult') || res.data.includes('<EnumerationResults')) {
              publicListable = true;
              for (const m of res.data.matchAll(/<(?:Key|Name)>([^<]{1,120})<\/(?:Key|Name)>/gi)) {
                if (sampleKeys.length < 4 && !m[1].startsWith('http')) {
                  sampleKeys.push(m[1]);
                }
              }
            }
          } else if (res.data && typeof res.data === 'object' && res.data.kind === 'storage#objects') {
            publicListable = true;
            const items = Array.isArray(res.data.items) ? res.data.items : [];
            for (const it of items.slice(0, 4)) {
              if (it?.name) sampleKeys.push(String(it.name));
            }
          }
        }

        probedBuckets.push({
          provider: c.provider,
          bucketUrl: c.bucketUrl,
          listUrl: c.listUrl,
          status: res.status,
          publicListable,
          sampleKeys,
        });

        if (publicListable) {
          const sensitiveKey = sampleKeys.some((k) =>
            /(?:\.env|\.sql|backup|dump|secret|token|user|kyc|passport|invoice|config|admin|private)/i.test(k)
          );
          findings.push({
            category: 'Cloud Storage & Buckets',
            type: `Publicly Listable ${c.provider} Bucket Exposed`,
            severity: sensitiveKey ? 'CRITICAL' : 'HIGH',
            owaspRef,
            proof: `Read-only listing probe to ${c.bucketUrl} returned HTTP 200${
              sampleKeys.length > 0 ? ` revealing objects: ${sampleKeys.join(', ')}` : ' with directory listing enabled.'
            }`,
            description:
              'Unauthenticated bucket listing exposes all stored files and object paths in your cloud storage bucket, allowing attackers to enumerate user uploads, backups, or private configuration assets.',
            remediation:
              c.provider === 'AWS S3'
                ? 'Enable S3 Block Public Access (BlockPublicAcls + BlockPublicPolicy) and restrict s3:ListBucket strictly to authenticated IAM roles.'
                : c.provider === 'Google Cloud Storage'
                ? 'Remove allUsers and allAuthenticatedUsers from Storage IAM bindings and enforce Public Access Prevention.'
                : 'Set Azure Storage Container Public Access Level to Private (no anonymous access) and use time-limited SAS tokens.',
          });
        }
      } catch {
        probedBuckets.push({
          provider: c.provider,
          bucketUrl: c.bucketUrl,
          listUrl: c.listUrl,
          status: 'Timeout',
          publicListable: false,
          sampleKeys: [],
        });
      }
    })
  );

  const anyExposed = probedBuckets.some((b) => b.publicListable);
  const testedCount = probedBuckets.filter((b) => typeof b.status === 'number').length;
  if (!anyExposed && testedCount > 0) {
    findings.push({
      category: 'Cloud Storage & Buckets',
      type: `Cloud Storage Bucket Listing Protected (${testedCount} Checked)`,
      severity: 'PASS',
      owaspRef,
      proof: `Probed ${probedBuckets
        .filter((b) => typeof b.status === 'number')
        .map((b) => `${b.bucketUrl} (HTTP ${b.status})`)
        .join(', ')} — anonymous directory listing blocked.`,
      description: 'Discovered cloud storage bucket URLs do not permit unauthenticated object listing.',
      remediation: 'Keep Public Access Prevention enabled and enforce signed URLs for private objects.',
    });
  }

  return { findings, probedBuckets };
}
