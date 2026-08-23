/**
 * Thin GitHub REST API wrapper using Node's native fetch -- deliberately
 * not an additional SDK dependency (@octokit/rest etc.): the only
 * third-party dependency this project accepts is the official `openai`
 * package itself (see package.json), consistent with the whole rationale
 * for building a repository-owned pipeline instead of adopting an opaque
 * third-party Action bundle.
 */

const API_BASE = 'https://api.github.com';

/**
 * @param {string} token
 * @param {string} path
 * @param {{method?: string, body?: object}} [options]
 */
async function request(token, path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    method: options.method ?? 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'Content-Type': 'application/json',
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  if (!response.ok) {
    // Deliberately does not include the response body: it can contain
    // detail a maintainer wouldn't want promoted into a job summary or PR
    // comment. The status code alone is enough for main.mjs's fail-open
    // handling to classify and log a safe, generic reason.
    const error = new Error(`GitHub API ${options.method ?? 'GET'} ${path} failed with HTTP ${response.status}`);
    error.status = response.status;
    throw error;
  }

  if (response.status === 204) return null;
  return response.json();
}

export function makeGitHubClient(token, ownerRepo) {
  const [owner, repo] = ownerRepo.split('/');

  return {
    getPullRequest: (prNumber) => request(token, `/repos/${owner}/${repo}/pulls/${prNumber}`),

    /** @returns {(page: number) => Promise<object[]>} */
    fetchFilesPage: (prNumber) => (page) =>
      request(token, `/repos/${owner}/${repo}/pulls/${prNumber}/files?per_page=100&page=${page}`),

    /** Paginates every issue comment on a PR (PRs are issues for commenting purposes). */
    listAllComments: async (prNumber) => {
      const all = [];
      for (let page = 1; ; page++) {
        const batch = await request(token, `/repos/${owner}/${repo}/issues/${prNumber}/comments?per_page=100&page=${page}`);
        if (!batch || batch.length === 0) break;
        all.push(...batch);
      }
      return all;
    },

    createComment: (prNumber, body) =>
      request(token, `/repos/${owner}/${repo}/issues/${prNumber}/comments`, { method: 'POST', body: { body } }),

    updateComment: (commentId, body) =>
      request(token, `/repos/${owner}/${repo}/issues/comments/${commentId}`, { method: 'PATCH', body: { body } }),
  };
}
