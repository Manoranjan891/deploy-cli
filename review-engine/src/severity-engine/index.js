/**
 * AuthGuardian AI — Severity Engine
 * ===================================
 * Calculates risk scores, severity distributions, deployment readiness,
 * and compliance scores based on aggregated findings.
 *
 * @module severity-engine
 */

const config = require('../../configs/review-config');

/**
 * Calculates the total risk score from an array of findings.
 *
 * @param {Array<object>} findings - Array of finding objects with .severity
 * @returns {number} Total weighted risk score
 */
function calculateRiskScore(findings) {
  if (!findings || findings.length === 0) return 0;

  return findings.reduce((score, finding) => {
    const level = config.severity.levels[finding.severity];
    return score + (level ? level.weight : 0);
  }, 0);
}

/**
 * Calculates normalized risk score (0–100).
 *
 * @param {Array<object>} findings
 * @returns {number} Score between 0 and 100
 */
function calculateNormalizedScore(findings) {
  if (!findings || findings.length === 0) return 0;
  const raw = calculateRiskScore(findings);
  // Logarithmic scaling to prevent extreme outliers
  const normalized = Math.min(100, Math.round((raw / (raw + 20)) * 100));
  return normalized;
}

/**
 * Calculates the severity distribution (count per level).
 *
 * @param {Array<object>} findings
 * @returns {object} { CRITICAL: n, HIGH: n, MEDIUM: n, LOW: n }
 */
function getSeverityDistribution(findings) {
  const distribution = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const finding of findings) {
    if (distribution.hasOwnProperty(finding.severity)) {
      distribution[finding.severity]++;
    }
  }
  return distribution;
}

/**
 * Determines deployment readiness status.
 *
 * @param {Array<object>} findings
 * @returns {object} { status, label, reason, canDeploy }
 */
function getDeploymentReadiness(findings) {
  const dist = getSeverityDistribution(findings);
  const riskScore = calculateRiskScore(findings);

  if (dist.CRITICAL > 0) {
    return {
      status: 'BLOCKED',
      label: '🚫 DEPLOYMENT BLOCKED',
      reason: `${dist.CRITICAL} CRITICAL finding(s) detected. Manual review and remediation required before deployment.`,
      canDeploy: false,
    };
  }

  if (dist.HIGH >= 3) {
    return {
      status: 'REQUIRES_APPROVAL',
      label: '⚠️ REQUIRES APPROVAL',
      reason: `${dist.HIGH} HIGH severity finding(s). Senior IAM engineer approval required.`,
      canDeploy: false,
    };
  }

  if (dist.HIGH > 0) {
    return {
      status: 'WARNING',
      label: '⚠️ DEPLOY WITH CAUTION',
      reason: `${dist.HIGH} HIGH severity finding(s). Review recommended before deployment.`,
      canDeploy: true,
    };
  }

  if (dist.MEDIUM > 0) {
    return {
      status: 'ADVISORY',
      label: '📋 ADVISORY',
      reason: `${dist.MEDIUM} MEDIUM severity finding(s). Consider addressing in next iteration.`,
      canDeploy: true,
    };
  }

  return {
    status: 'PASS',
    label: '✅ READY TO DEPLOY',
    reason: 'No significant security or IAM risks detected.',
    canDeploy: true,
  };
}

/**
 * Calculates a compliance score (0–100).
 * Higher is better. Penalizes based on findings.
 *
 * @param {Array<object>} findings
 * @param {number} totalFiles - Total files reviewed
 * @returns {object} { score, grade, label }
 */
function calculateComplianceScore(findings, totalFiles) {
  if (totalFiles === 0) return { score: 100, grade: 'A', label: 'Excellent' };

  const riskScore = calculateRiskScore(findings);
  // Scale penalty relative to number of files
  const penalty = Math.min(100, (riskScore / Math.max(1, totalFiles)) * 10);
  const score = Math.max(0, Math.round(100 - penalty));

  let grade, label;
  if (score >= 90)      { grade = 'A'; label = 'Excellent'; }
  else if (score >= 80) { grade = 'B'; label = 'Good'; }
  else if (score >= 70) { grade = 'C'; label = 'Acceptable'; }
  else if (score >= 60) { grade = 'D'; label = 'Needs Improvement'; }
  else                  { grade = 'F'; label = 'Critical Attention Required'; }

  return { score, grade, label };
}

/**
 * Calculates a secure coding score (0–100) for code review findings.
 *
 * @param {Array<object>} codeFindings
 * @param {number} totalCodeFiles
 * @returns {object} { score, grade, label }
 */
function calculateSecureCodingScore(codeFindings, totalCodeFiles) {
  return calculateComplianceScore(codeFindings, totalCodeFiles);
}

/**
 * Determines if a finding should trigger a deployment block.
 *
 * @param {object} finding
 * @returns {boolean}
 */
function isBlockingFinding(finding) {
  return finding.severity === 'CRITICAL';
}

/**
 * Generates a summary object for all findings.
 *
 * @param {object} params
 * @param {Array<object>} params.deploymentFindings
 * @param {Array<object>} params.codeFindings
 * @param {number} params.totalFiles
 * @param {number} params.totalCodeFiles
 * @returns {object} Comprehensive summary
 */
function generateSummary({ deploymentFindings = [], codeFindings = [], totalFiles = 0, totalCodeFiles = 0 }) {
  const allFindings = [...deploymentFindings, ...codeFindings];
  const distribution = getSeverityDistribution(allFindings);
  const riskScore = calculateNormalizedScore(allFindings);
  const readiness = getDeploymentReadiness(allFindings);
  const compliance = calculateComplianceScore(deploymentFindings, totalFiles);
  const secureCoding = calculateSecureCodingScore(codeFindings, totalCodeFiles);

  return {
    totalFindings: allFindings.length,
    deploymentFindings: deploymentFindings.length,
    codeFindings: codeFindings.length,
    distribution,
    riskScore,
    readiness,
    compliance,
    secureCoding,
    timestamp: new Date().toISOString(),
    engineVersion: config.meta.version,
  };
}

module.exports = {
  calculateRiskScore,
  calculateNormalizedScore,
  getSeverityDistribution,
  getDeploymentReadiness,
  calculateComplianceScore,
  calculateSecureCodingScore,
  isBlockingFinding,
  generateSummary,
};
