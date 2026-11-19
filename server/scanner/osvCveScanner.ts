import axios from 'axios';

export interface OsvQueryPackage {
  ecosystem: 'Maven' | 'npm';
  name: string;
  version: string;
  sourceFile: string;
}

export interface CveMatchSummary {
  packageName: string;
  ecosystem: 'Maven' | 'npm';
  version: string;
  cveIds: string[];
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  summary: string;
  fixedVersion?: string;
}

export interface OsvScanFinding {
  category: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'PASS';
  proof: string;
  description: string;
  remediation: string;
  owaspRef: string;
}

export interface OsvAuditResult {
  findings: OsvScanFinding[];
  inspectedDependenciesCount: number;
  vulnerableDependencies: CveMatchSummary[];
}

export function extractMavenVersionsFromZipEntries(
  entries: Array<{ entryName: string; readText: () => string }>
): OsvQueryPackage[] {
  const packages: OsvQueryPackage[] = [];
  const seen = new Set<string>();

  for (const e of entries) {
    const cleanPath = e.entryName.replace(/^base\/root\//i, '');
    const m = cleanPath.match(/^META-INF\/([a-zA-Z0-9.-]+_[a-zA-Z0-9._-]+)\.version$/i);
    if (!m) continue;

    const rawId = m[1];
    const underscoreIdx = rawId.indexOf('_');
    if (underscoreIdx <= 0) continue;

    const groupId = rawId.slice(0, underscoreIdx);
    const artifactId = rawId.slice(underscoreIdx + 1);
    const version = e.readText().trim().split(/\r?\n/)[0]?.trim() || '';
    if (!version || !/^\d+\.\d+/.test(version) || version.length > 32) continue;

    const mavenName = `${groupId}:${artifactId}`;
    const key = `${mavenName}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);

    packages.push({
      ecosystem: 'Maven',
      name: mavenName,
      version,
      sourceFile: e.entryName,
    });
  }

  // Prioritize security-relevant / common third-party SDKs over standard androidx annotations
  packages.sort((a, b) => {
    const score = (n: string) =>
      /(?:okhttp|retrofit|gson|netty|jackson|commons|bouncycastle|log4j|firebase|stripe|razorpay|webkit|ExoPlayer|coil|glide)/i.test(
        n
      )
        ? 0
        : n.startsWith('androidx.')
          ? 2
          : 1;
    return score(a.name) - score(b.name);
  });

  return packages.slice(0, 22);
}

export function extractNpmVersionsFromWebAssets(
  html: string,
  collectedScripts: Array<{ url: string; content: string }>
): OsvQueryPackage[] {
  const packages: OsvQueryPackage[] = [];
  const seen = new Set<string>();

  const addPkg = (name: string, version: string, sourceFile: string) => {
    if (!version || !/^\d+\.\d+\.\d+$/.test(version)) return;
    const key = `${name}@${version}`;
    if (seen.has(key)) return;
    seen.add(key);
    packages.push({ ecosystem: 'npm', name, version, sourceFile });
  };

  const specs: Array<{ name: string; regex: RegExp }> = [
    { name: 'jquery', regex: /(?:jquery[./@-]|jQuery JavaScript Library v)(\d+\.\d+\.\d+)/i },
    { name: 'lodash', regex: /(?:lodash(?:\.min)?\.js(?:@|\/|-)|lodash@|@license Lodash[^0-9]{0,20})(\d+\.\d+\.\d+)/i },
    { name: 'axios', regex: /(?:axios(?:@|\/|\/dist\/axios(?:\.min)?\.js@?)|"axios":\s*"\^?)(\d+\.\d+\.\d+)/i },
    { name: 'bootstrap', regex: /(?:bootstrap(?:\.min)?\.(?:js|css)(?:@|\/|-)|Bootstrap v)(\d+\.\d+\.\d+)/i },
    { name: 'dompurify', regex: /(?:dompurify(?:@|\/)|DOMPurify\s+v?)(\d+\.\d+\.\d+)/i },
    { name: 'marked', regex: /(?:marked(?:@|\/)|"marked":\s*"\^?)(\d+\.\d+\.\d+)/i },
    { name: 'moment', regex: /(?:moment(?:\.min)?\.js(?:@|\/)|moment\.version\s*=\s*["'])(\d+\.\d+\.\d+)/i },
    { name: 'handlebars', regex: /(?:handlebars(?:\.min)?\.js(?:@|\/)|Handlebars\s+v)(\d+\.\d+\.\d+)/i },
    { name: 'next', regex: /"nextVersion":\s*"(\d+\.\d+\.\d+)"/ },
    { name: 'react', regex: /(?:react(?:\.production\.min)?\.js(?:@|\/)|react@)(\d+\.\d+\.\d+)/i },
    { name: 'crypto-js', regex: /(?:crypto-js(?:@|\/))(\d+\.\d+\.\d+)/i },
  ];

  const sources: Array<{ label: string; text: string }> = [
    { label: 'HTML Document', text: html.slice(0, 200000) },
    ...collectedScripts.slice(0, 12).map((s) => ({
      label: s.url,
      text: `${s.url}\n${s.content.slice(0, 25000)}`,
    })),
  ];

  for (const src of sources) {
    for (const spec of specs) {
      const m = src.text.match(spec.regex);
      if (m?.[1]) {
        addPkg(spec.name, m[1], src.label);
      }
    }
  }

  return packages.slice(0, 18);
}

function classifyOsvSeverity(vulns: any[]): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
  let rank = 1; // MEDIUM default for known CVE
  for (const v of vulns) {
    const dbSev = String(v?.database_specific?.severity || '').toUpperCase();
    if (dbSev === 'CRITICAL') return 'CRITICAL';
    if (dbSev === 'HIGH') rank = Math.max(rank, 2);

    if (Array.isArray(v?.severity)) {
      for (const s of v.severity) {
        const sc = String(s?.score || '');
        if (/CVSS:3\.\d\/AV:N\/AC:L\/PR:N\/UI:N/i.test(sc)) {
          rank = Math.max(rank, 3);
        }
      }
    }
  }
  return rank >= 3 ? 'CRITICAL' : rank === 2 ? 'HIGH' : 'MEDIUM';
}

function extractFixedVersion(vulns: any[], pkgName: string): string | undefined {
  for (const v of vulns) {
    const affected = Array.isArray(v?.affected) ? v.affected : [];
    for (const a of affected) {
      if (a?.package?.name && a.package.name !== pkgName) continue;
      const ranges = Array.isArray(a?.ranges) ? a.ranges : [];
      for (const r of ranges) {
        const events = Array.isArray(r?.events) ? r.events : [];
        for (const ev of events) {
          if (typeof ev?.fixed === 'string' && ev.fixed) {
            return ev.fixed;
          }
        }
      }
    }
  }
  return undefined;
}

export async function queryOsvCveDatabase(
  packages: OsvQueryPackage[],
  options: { isApk: boolean }
): Promise<OsvAuditResult> {
  if (packages.length === 0) {
    return { findings: [], inspectedDependenciesCount: 0, vulnerableDependencies: [] };
  }

  const owaspRef = options.isApk ? 'MASVS-CODE-1' : 'OWASP-A06';
  const vulnerableDependencies: CveMatchSummary[] = [];
  const findings: OsvScanFinding[] = [];

  try {
    const batchPayload = {
      queries: packages.map((p) => ({
        version: p.version,
        package: {
          name: p.name,
          ecosystem: p.ecosystem,
        },
      })),
    };

    const batchRes = await axios.post('https://api.osv.dev/v1/querybatch', batchPayload, {
      timeout: 3200,
      validateStatus: () => true,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'CheckMyAPK-OSV-Auditor/1.0 (+https://checkmyapk.com)',
      },
    });

    if (batchRes.status !== 200 || !Array.isArray(batchRes.data?.results)) {
      return { findings: [], inspectedDependenciesCount: packages.length, vulnerableDependencies: [] };
    }

    // Collect packages that actually returned vulnerable advisory IDs
    const hitItems: Array<{ pkg: OsvQueryPackage; ids: string[] }> = [];
    for (let i = 0; i < packages.length; i++) {
      const vulns = batchRes.data.results[i]?.vulns;
      if (Array.isArray(vulns) && vulns.length > 0) {
        hitItems.push({
          pkg: packages[i],
          ids: vulns.map((v: any) => String(v.id)).slice(0, 4),
        });
      }
    }

    // Fetch detailed CVE aliases/severity for up to 5 matched packages (parallel fast lookups)
    const detailedHits = await Promise.all(
      hitItems.slice(0, 5).map(async (item) => {
        const vulnDetails = await Promise.all(
          item.ids.slice(0, 2).map(async (id) => {
            try {
              const r = await axios.get(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, {
                timeout: 2200,
                validateStatus: () => true,
              });
              return r.status === 200 ? r.data : { id };
            } catch {
              return { id };
            }
          })
        );

        const cveIds: string[] = [];
        for (const vd of vulnDetails) {
          const aliases = Array.isArray(vd?.aliases) ? vd.aliases : [];
          const cve = aliases.find((a: any) => typeof a === 'string' && a.startsWith('CVE-'));
          cveIds.push(cve || vd.id);
        }

        const severity = classifyOsvSeverity(vulnDetails);
        const fixedVersion = extractFixedVersion(vulnDetails, item.pkg.name);
        const firstSummary = String(vulnDetails[0]?.summary || vulnDetails[0]?.details || '').slice(0, 180);

        return {
          pkg: item.pkg,
          totalVulnCount: item.ids.length,
          cveIds,
          severity,
          fixedVersion,
          firstSummary,
        };
      })
    );

    for (const hit of detailedHits) {
      const match: CveMatchSummary = {
        packageName: hit.pkg.name,
        ecosystem: hit.pkg.ecosystem,
        version: hit.pkg.version,
        cveIds: hit.cveIds,
        severity: hit.severity,
        summary: hit.firstSummary || `Known vulnerability advisories matched in Google OSV database.`,
        fixedVersion: hit.fixedVersion,
      };
      vulnerableDependencies.push(match);

      findings.push({
        category: 'Software Supply-Chain & CVE',
        type: `Known Vulnerable Library (${hit.pkg.name}@${hit.pkg.version})`,
        severity: hit.severity,
        owaspRef,
        proof: `Google OSV.dev matched ${hit.totalVulnCount} advisory/ies for ${hit.pkg.ecosystem}:${hit.pkg.name}@${hit.pkg.version} (${hit.cveIds.join(', ')})${
          hit.pkg.sourceFile ? ` via ${hit.pkg.sourceFile}` : ''
        }.`,
        description: `${hit.firstSummary || `This version of ${hit.pkg.name} has documented CVEs in public advisory feeds.`}`,
        remediation: hit.fixedVersion
          ? `Upgrade ${hit.pkg.name} from ${hit.pkg.version} to version ${hit.fixedVersion} or newer and rebuild.`
          : `Upgrade ${hit.pkg.name} to the latest patched release and run dependency vulnerability audits in CI.`,
      });
    }

    if (vulnerableDependencies.length === 0 && packages.length > 0) {
      findings.push({
        category: 'Software Supply-Chain & CVE',
        type: `OSV.dev Dependency CVE Check Clean (${packages.length} Inspected)`,
        severity: 'PASS',
        owaspRef,
        proof: `Queried Google OSV.dev database against ${packages.length} fingerprinted dependency version(s) (${packages
          .slice(0, 4)
          .map((p) => `${p.name}@${p.version}`)
          .join(', ')}) — 0 known advisories matched.`,
        description: 'None of the fingerprinted dependency versions matched active CVE advisories in OSV.dev.',
        remediation: 'Continue automated dependency scanning with Dependabot / OSV-Scanner on every build.',
      });
    }
  } catch {
    // Live OSV query timeout/offline failsafe: gracefully skip without disrupting primary audit
  }

  return {
    findings,
    inspectedDependenciesCount: packages.length,
    vulnerableDependencies,
  };
}
