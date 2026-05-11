/**
 * AuthGuardian AI — GitHub Comment Publisher
 * =============================================
 * Publishes review results as GitHub PR comments and workflow summaries.
 * Uses GitHub's native API (via GITHUB_TOKEN) — no external dependencies.
 *
 * @module github-comment-publisher
 */

const https = require('https');
const fs = require('fs');
const path = require('path');
const config = require('../../configs/review-config');

/**
 * Publishes a PR comment with review results.
 * Creates a new comment or updates an existing AuthGuardian comment.
 *
 * @param {string} commentBody - Markdown content for the PR comment
 * @returns {Promise<object>} { success, commentId, url }
 */
async function publishPrComment(commentBody) {
  const token = process.env.GITHUB_TOKEN;
  const eventPath = process.env.GITHUB_EVENT_PATH;
  const repository = process.env.GITHUB_REPOSITORY;

  if (!token || !repository) {
    console.log('[AuthGuardian] Not in GitHub Actions environment or missing GITHUB_TOKEN. Skipping PR comment.');
    return { success: false, reason: 'Not in GitHub Actions' };
  }

  // Determine PR number
  let prNumber = process.env.AUTHGUARDIAN_PR_NUMBER;

  if (!prNumber && eventPath) {
    try {
      const event = JSON.parse(fs.readFileSync(eventPath, 'utf8'));
      prNumber = event.pull_request?.number || event.number;
    } catch {
      // Not a PR event
    }
  }

  if (!prNumber) {
    console.log('[AuthGuardian] No PR number found. Skipping PR comment.');
    return { success: false, reason: 'No PR number' };
  }

  const [owner, repo] = repository.split('/');

  try {
    // Check for existing AuthGuardian comment
    const existingCommentId = await findExistingComment(owner, repo, prNumber, token);

    if (existingCommentId) {
      // Update existing comment
      const result = await updateComment(owner, repo, existingCommentId, commentBody, token);
      console.log(`[AuthGuardian] Updated PR comment #${existingCommentId}`);
      return { success: true, commentId: existingCommentId, url: result.html_url, action: 'updated' };
    } else {
      // Create new comment
      const result = await createComment(owner, repo, prNumber, commentBody, token);
      console.log(`[AuthGuardian] Created PR comment #${result.id}`);
      return { success: true, commentId: result.id, url: result.html_url, action: 'created' };
    }
  } catch (err) {
    console.error(`[AuthGuardian] Failed to publish PR comment: ${err.message}`);
    return { success: false, reason: err.message };
  }
}

/**
 * Writes content to the GitHub Actions job summary.
 *
 * @param {string} summaryContent - Markdown content
 * @returns {boolean} Whether write succeeded
 */
function writeJobSummary(summaryContent) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;

  if (!summaryPath) {
    console.log('[AuthGuardian] GITHUB_STEP_SUMMARY not available. Skipping job summary.');
    return false;
  }

  try {
    fs.appendFileSync(summaryPath, summaryContent + '\n');
    console.log('[AuthGuardian] Job summary written successfully.');
    return true;
  } catch (err) {
    console.error(`[AuthGuardian] Failed to write job summary: ${err.message}`);
    return false;
  }
}

/**
 * Saves markdown reports to the output directory.
 *
 * @param {object} reports - { deploymentReport, codeReviewReport, jobSummary }
 * @param {string} [outputDir] - Output directory path
 * @returns {object} { paths }
 */
function saveReports(reports, outputDir) {
  const dir = outputDir || path.resolve(process.cwd(), config.reporting.outputDir);

  // Ensure output directory exists
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const paths = {};

  if (reports.deploymentReport) {
    const filePath = path.join(dir, config.reporting.deploymentReportFile);
    fs.writeFileSync(filePath, reports.deploymentReport, 'utf8');
    paths.deploymentReport = filePath;
    console.log(`[AuthGuardian] Deployment report saved: ${filePath}`);
  }

  if (reports.codeReviewReport) {
    const filePath = path.join(dir, config.reporting.codeReviewReportFile);
    fs.writeFileSync(filePath, reports.codeReviewReport, 'utf8');
    paths.codeReviewReport = filePath;
    console.log(`[AuthGuardian] Code review report saved: ${filePath}`);
  }

  if (reports.summaryReport) {
    const filePath = path.join(dir, config.reporting.summaryReportFile);
    fs.writeFileSync(filePath, reports.summaryReport, 'utf8');
    paths.summaryReport = filePath;
    console.log(`[AuthGuardian] Summary report saved: ${filePath}`);
  }

  return { paths };
}

// ─────────────────────────────────────────────────────────────
// GITHUB API HELPERS
// ─────────────────────────────────────────────────────────────

/**
 * Finds an existing AuthGuardian comment on a PR.
 */
async function findExistingComment(owner, repo, prNumber, token) {
  const comments = await githubApiRequest(
    'GET',
    `/repos/${owner}/${repo}/issues/${prNumber}/comments?per_page=100`,
    token
  );

  if (Array.isArray(comments)) {
    const existing = comments.find(c =>
      c.body && c.body.includes(config.github.commentHeader)
    );
    return existing ? existing.id : null;
  }

  return null;
}

/**
 * Creates a new PR comment.
 */
async function createComment(owner, repo, prNumber, body, token) {
  return githubApiRequest(
    'POST',
    `/repos/${owner}/${repo}/issues/${prNumber}/comments`,
    token,
    { body }
  );
}

/**
 * Updates an existing PR comment.
 */
async function updateComment(owner, repo, commentId, body, token) {
  return githubApiRequest(
    'PATCH',
    `/repos/${owner}/${repo}/issues/comments/${commentId}`,
    token,
    { body }
  );
}

/**
 * Makes a GitHub API request using Node.js https module (no dependencies).
 */
function githubApiRequest(method, path, token, data = null) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.github.com',
      port: 443,
      path,
      method,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'AuthGuardian-AI',
        'Content-Type': 'application/json',
      },
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(parsed);
          } else {
            reject(new Error(`GitHub API ${res.statusCode}: ${parsed.message || body}`));
          }
        } catch {
          reject(new Error(`GitHub API response parse error: ${body.substring(0, 200)}`));
        }
      });
    });

    req.on('error', reject);

    if (data) {
      req.write(JSON.stringify(data));
    }

    req.end();
  });
}

module.exports = {
  publishPrComment,
  writeJobSummary,
  saveReports,
};
