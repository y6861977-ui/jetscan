"use server";

// NEGATIVE (WEB-SECRET-001): Server Actions module.
const GITHUB = "@@GITHUB_TOKEN@@";

export async function star(repo: string) {
  return fetch(`https://api.github.com/user/starred/${repo}`, {
    method: "PUT",
    headers: { Authorization: `token ${GITHUB}` },
  });
}
