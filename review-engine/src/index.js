/**
 * ════════════════════════════════════════════════════════════════════════════
 *   AuthGuardian AI — Main Orchestrator
 * ════════════════════════════════════════════════════════════════════════════
 *
 *   Enterprise-grade AI-assisted IAM governance and secure deployment
 *   review platform for Auth0 CI/CD pipelines.
 *
 *   This is the main entry point. It orchestrates:
 *     1. Diff parsing — detect changed Auth0 configuration files
 *     2. Deployment review — analyze IAM/security risks in config
 *     3. Code review — analyze Auth0 Actions/Rules/Hooks for vulnerabilities
 *     4. Severity scoring — calculate risk, compliance, readiness
 *     5. Report generation — markdown reports, PR comments, job summaries
 *
 *   Usage:
 *     node src/index.js                    # Run all reviews
 *     node src/index.js --mode deployment  # Deployment review only
 *     node src/index.js --mode code        # Code review only
 *     node src/index.js --mode all         # Both (default)
 *
 *   Environment Variables:
 *     AUTHGUARDIAN_BASE_REF     — Git ref to diff against (default: origin/main)
 *     AUTHGUARDIAN_PR_NUMBER    — PR number for comments
 *     AUTHGUARDIAN_BLOCK_ON_CRITICAL — Exit non-zero on critical findings (default: false)
 *     GITHUB_TOKEN              — Required for PR comments
 *     GITHUB_STEP_SUMMARY       — GitHub Actions summary file path
 *     GITHUB_OUTPUT             — GitHub Actions output file path
 *
 * ════════════════════════════════════════════════════════════════════════════
 */

const path = require('path');
const config = require('../configs/review-config');
const diffParser = require('./diff-parser');
const deploymentReview = require('./deployment-review');
const codeReview = require('./code-review');
const severityEngine = require('./severity-engine');
const markdownGenerator = require('./markdown-generator');
const githubPublisher = require('./github-comment-publisher');
const utils = require('./utils');

// ─────────────────────────────────────────────────────────────
// MAIN EXECUTION
// ─────────────────────────────────────────────────────────────

async function main() {
  const startTime = Date.now();
  const runId = utils.generateRunId();
  const envInfo = utils.getEnvironmentInfo();
  const mode = parseMode();

  console.log('');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  🛡️  AuthGuardian AI — IAM Governance & Security Review');
  console.log(`  Version: ${config.meta.version}`);
  console.log(`  Run ID:  ${runId}`);
  console.log(`  Mode:    ${mode}`);
  console.log(`  Branch:  ${envInfo.branch}`);
  console.log(`  Commit:  ${envInfo.commit}`);
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('');

  // ── Step 1: Parse Changed Files ──────────────────────────────
  console.log('▶ [Step 1/5] Parsing changed Auth0 files...');

  // AUTHGUARDIAN_SCAN_DIR allows scanning a specific directory (e.g., auth0/exported/)
  // instead of relying on git diff. Used when configs are generated at runtime.
  const scanDir = process.env.AUTHGUARDIAN_SCAN_DIR;
  const workDir = scanDir ? path.resolve(scanDir) : path.resolve(process.cwd(), '..');

  if (scanDir) {
    console.log(`   Scan mode: direct filesystem scan of ${workDir}`);
  }

  const changedFiles = diffParser.getChangedFiles({
    workDir,
  });

  if (changedFiles.length === 0) {
    console.log('');
    console.log('✅ No Auth0 configuration changes detected. Nothing to review.');
    console.log('');
    const noChangeSummary = '## 🛡️ AuthGuardian AI — No Changes Detected\n\n' +
      '> No Auth0 configuration changes were found in this deployment.\n' +
      '> Review skipped. Deployment can proceed.\n';
    githubPublisher.writeJobSummary(noChangeSummary);
    githubPublisher.saveReports({ summaryReport: noChangeSummary });
    setOutputs({ findings: 0, status: 'PASS', canDeploy: true });
    return;
  }

  console.log(`   Found ${changedFiles.length} changed Auth0 file(s)`);
  const byChange = diffParser.groupByChangeType(changedFiles);
  console.log(`   Added: ${byChange.added.length} | Modified: ${byChange.modified.length} | Deleted: ${byChange.deleted.length}`);
  console.log('');

  // ── Step 2: Deployment Review ────────────────────────────────
  let deploymentResult = { findings: [], reviewedFiles: [], stats: { totalFiles: 0, added: 0, modified: 0, deleted: 0, resourceTypes: [], totalFindings: 0 } };

  if (mode === 'all' || mode === 'deployment') {
    console.log('▶ [Step 2/5] Running deployment configuration review...');
    deploymentResult = deploymentReview.runDeploymentReview(changedFiles);
    console.log(`   Reviewed ${deploymentResult.stats.totalFiles} file(s)`);
    console.log(`   Found ${deploymentResult.stats.totalFindings} deployment finding(s)`);
    console.log('');
  }

  // ── Step 3: Code Review ──────────────────────────────────────
  let codeResult = { findings: [], reviewedFiles: [], stats: { totalCodeFiles: 0, totalFindings: 0 } };

  if (mode === 'all' || mode === 'code') {
    console.log('▶ [Step 3/5] Running secure code review...');
    codeResult = codeReview.runCodeReview(changedFiles);
    console.log(`   Reviewed ${codeResult.stats.totalCodeFiles} code file(s)`);
    console.log(`   Found ${codeResult.stats.totalFindings} code finding(s)`);
    console.log('');
  }

  // ── Step 4: Severity Analysis ────────────────────────────────
  console.log('▶ [Step 4/5] Calculating severity scores and readiness...');
  const summary = severityEngine.generateSummary({
    deploymentFindings: deploymentResult.findings,
    codeFindings: codeResult.findings,
    totalFiles: deploymentResult.stats.totalFiles,
    totalCodeFiles: codeResult.stats.totalCodeFiles,
  });

  console.log(`   Risk Score:       ${summary.riskScore}/100`);
  console.log(`   Compliance:       ${summary.compliance.score}/100 (${summary.compliance.grade})`);
  console.log(`   Secure Coding:    ${summary.secureCoding.score}/100 (${summary.secureCoding.grade})`);
  console.log(`   Readiness:        ${summary.readiness.label}`);
  console.log(`   Findings:         🔴${summary.distribution.CRITICAL} 🟠${summary.distribution.HIGH} 🟡${summary.distribution.MEDIUM} 🔵${summary.distribution.LOW}`);
  console.log('');

  // ── Step 5: Generate Reports & Publish ───────────────────────
  console.log('▶ [Step 5/5] Generating reports and publishing...');

  // Generate markdown reports
  const deploymentReport = markdownGenerator.generateDeploymentReport(deploymentResult, summary);
  const codeReviewReport = markdownGenerator.generateCodeReviewReport(codeResult, summary);
  const jobSummary = markdownGenerator.generateJobSummary(deploymentResult, codeResult, summary);
  const prComment = markdownGenerator.generatePrComment(deploymentResult, codeResult, summary);

  // Save reports to disk
  const reportPaths = githubPublisher.saveReports({
    deploymentReport,
    codeReviewReport,
    summaryReport: jobSummary,
  });

  console.log('   Reports saved to disk.');

  // Write GitHub Actions job summary
  if (config.github.enableJobSummary) {
    githubPublisher.writeJobSummary(jobSummary);
  }

  // Publish PR comment
  if (config.github.enablePrComments) {
    const commentResult = await githubPublisher.publishPrComment(prComment);
    if (commentResult.success) {
      console.log(`   PR comment ${commentResult.action}: ${commentResult.url || 'N/A'}`);
    }
  }

  // Set GitHub Actions outputs
  setOutputs({
    findings: summary.totalFindings,
    critical: summary.distribution.CRITICAL,
    high: summary.distribution.HIGH,
    riskScore: summary.riskScore,
    complianceScore: summary.compliance.score,
    secureCodingScore: summary.secureCoding.score,
    status: summary.readiness.status,
    canDeploy: summary.readiness.canDeploy,
  });

  // ── Final Summary ────────────────────────────────────────────
  const duration = utils.formatDuration(Date.now() - startTime);

  console.log('');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  🛡️  AuthGuardian AI — Review Complete');
  console.log(`  ${summary.readiness.label}`);
  console.log(`  Total Findings: ${summary.totalFindings}`);
  console.log(`  Risk Score: ${summary.riskScore}/100`);
  console.log(`  Duration: ${duration}`);
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('');

  // Audit log
  if (config.enterprise.auditLogging) {
    const audit = utils.createAuditEntry({
      action: 'REVIEW_COMPLETED',
      details: {
        runId,
        mode,
        duration,
        filesReviewed: changedFiles.length,
        readiness: summary.readiness.status,
      },
      findings: [...deploymentResult.findings, ...codeResult.findings],
    });
    console.log(`[Audit] ${JSON.stringify(audit)}`);
  }

  // Exit with failure if configured to block on critical findings
  const blockOnCritical = process.env.AUTHGUARDIAN_BLOCK_ON_CRITICAL === 'true';
  if (blockOnCritical && summary.distribution.CRITICAL > 0) {
    console.error(`\n⛔ BLOCKED: ${summary.distribution.CRITICAL} CRITICAL finding(s). Set AUTHGUARDIAN_BLOCK_ON_CRITICAL=false to override.`);
    process.exit(1);
  }
}

// ─────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────

/**
 * Parses the review mode from CLI args or environment.
 */
function parseMode() {
  const args = process.argv.slice(2);
  const modeIndex = args.indexOf('--mode');
  if (modeIndex !== -1 && args[modeIndex + 1]) {
    return args[modeIndex + 1];
  }
  return process.env.AUTHGUARDIAN_MODE || 'all';
}

/**
 * Writes an empty summary when no changes detected.
 */
function writeEmptySummary() {
  const summary = '## 🛡️ AuthGuardian AI — No Changes Detected\n\n' +
    '> No Auth0 configuration changes were found in this deployment.\n' +
    '> Review skipped. Deployment can proceed.\n';

  githubPublisher.writeJobSummary(summary);
}

/**
 * Sets GitHub Actions output variables.
 */
function setOutputs(outputs) {
  for (const [key, value] of Object.entries(outputs)) {
    utils.setGitHubOutput(`authguardian_${key}`, String(value));
  }
}

// ── Execute ────────────────────────────────────────────────────
main().catch(err => {
  console.error(`\n⛔ AuthGuardian AI encountered a fatal error:\n${err.stack || err.message}`);
  process.exit(1);
});
