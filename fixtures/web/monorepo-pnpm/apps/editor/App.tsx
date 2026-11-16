// POSITIVE line 3 (WEB-SECRET-001): client module at the root of a Vite app without src/.

const GITHUB = "@@GITHUB_TOKEN@@";

export function App() {
  return <p>{GITHUB.length}</p>;
}
