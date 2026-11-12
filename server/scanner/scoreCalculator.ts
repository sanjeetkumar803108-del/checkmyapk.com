export interface SecurityReport {
  targetUrl: string;
  scanTimestamp: string;
  score: number;
  grade: 'A+' | 'A' | 'B' | 'C' | 'F';
  riskLevel: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
  summaryCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    pass: number;
  };
  findings: Array<{
    category: string;
    type: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'PASS';
    proof: string;
    description: string;
    remediation: string;
    owaspRef?: string;
  }>;
  aiExecutiveSummary?: string;
}

export function computeSecurityScore(targetUrl: string, rawFindings: any[]): SecurityReport {
  let score = 100;
  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;
  let pass = 0;

  for (const f of rawFindings) {
    if (f.severity === 'CRITICAL') {
      score -= 30;
      critical++;
    } else if (f.severity === 'HIGH') {
      score -= 15;
      high++;
    } else if (f.severity === 'MEDIUM') {
      score -= 8;
      medium++;
    } else if (f.severity === 'LOW') {
      score -= 3;
      low++;
    } else if (f.severity === 'PASS') {
      pass++;
    }
  }

  score = Math.max(0, Math.min(100, score));

  let grade: 'A+' | 'A' | 'B' | 'C' | 'F' = 'F';
  let riskLevel: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL' = 'CRITICAL';

  if (score >= 95) {
    grade = 'A+';
    riskLevel = 'LOW';
  } else if (score >= 85) {
    grade = 'A';
    riskLevel = 'LOW';
  } else if (score >= 70) {
    grade = 'B';
    riskLevel = 'MODERATE';
  } else if (score >= 55) {
    grade = 'C';
    riskLevel = 'HIGH';
  } else {
    grade = 'F';
    riskLevel = 'CRITICAL';
  }

  return {
    targetUrl,
    scanTimestamp: new Date().toISOString(),
    score,
    grade,
    riskLevel,
    summaryCounts: { critical, high, medium, low, pass },
    findings: rawFindings
  };
}

