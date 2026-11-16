"use client";

// NEGATIVE (WEB-SECRET-001): Storybook stories are not part of the production bundle.
export const WithToken = { args: { token: "@@GITHUB_TOKEN@@" } };
