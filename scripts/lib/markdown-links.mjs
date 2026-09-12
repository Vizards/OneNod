import { marked } from "marked";

export function markdownLinks(source, { includeImages = false } = {}) {
  const targets = [];
  marked.walkTokens(marked.lexer(source), (token) => {
    if (token.type === "link" || (includeImages && token.type === "image")) {
      targets.push(token.href);
    }
  });
  return targets;
}
