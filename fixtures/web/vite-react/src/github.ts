// Reads the VITE_ token flagged in .env (cross-referenced in that finding).
export const github = (path: string) =>
  fetch(`https://api.github.com${path}`, {
    headers: { Authorization: `token ${import.meta.env.VITE_GITHUB_TOKEN}` },
  });
