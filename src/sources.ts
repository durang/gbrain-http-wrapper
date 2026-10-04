/**
 * Server-side R2 stamp helpers. Pure functions (no I/O) so they are testable without a DB.
 */

/** Map a registered OAuth client's name to the R2 channel it should be stamped as. */
export function channelFromClientName(name: string | null | undefined): string | null {
  const n = (name || '').toLowerCase();
  if (/grok/.test(n)) return 'grok';
  if (/chatgpt|openai/.test(n)) return 'chatgpt-app';
  if (/claude/.test(n)) return 'claude-ai-web';
  return null;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Add the wrapper's own stamp to the frontmatter's `sources:` list.
 *
 * The previous implementation did `yamlBlock.replace(/(sources:.*)/s, ...)`. With the `s`
 * flag `.*` swallows everything AFTER `sources:`, so the new entry landed at the end of the
 * whole frontmatter instead of the end of the list. Whenever another key followed `sources`
 * (e.g. `effective_date`, which is the order the R2 → R6 rules produce) the result was
 * invalid YAML and the write failed.
 *
 *  - the entry goes at the end of the existing list, in the list's own indentation style
 *  - no `sources:` yet → one is created at the end
 *  - the client already stamped this channel → nothing is added (no duplicate)
 *  - flow style (`sources: [{...}]`) → left untouched rather than risk corrupting it
 */
export function addSourceEntry(yamlBlock: string, channel: string, date: string): string {
  const lines = yamlBlock.split('\n');
  const i = lines.findIndex((l) => /^sources:/.test(l));
  const mk = (ind: string) => [
    `${ind}- date: "${date}"`,
    `${ind}  channel: "${channel}"`,
    `${ind}  stamped_by: "wrapper"`,
  ];
  if (i === -1) return yamlBlock.replace(/\s+$/, '') + '\nsources:\n' + mk('  ').join('\n');

  const head = lines[i].replace(/\s+#.*$/, '').trim();
  if (head !== 'sources:' && head !== 'sources: []') return yamlBlock;

  let j = i + 1;
  while (j < lines.length && (/^\s+\S/.test(lines[j]) || /^-(\s|$)/.test(lines[j]))) j++;

  const block = lines.slice(i + 1, j).join('\n');
  if (new RegExp(`channel:\\s*["']?${escapeRe(channel)}["']?\\s*$`, 'm').test(block)) return yamlBlock;

  const ind = (block.match(/^(\s*)-/m) || [, '  '])[1] as string;
  lines[i] = 'sources:';
  lines.splice(j, 0, ...mk(ind));
  return lines.join('\n');
}
