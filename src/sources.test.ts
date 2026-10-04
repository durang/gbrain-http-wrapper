import { describe, expect, test } from 'bun:test';
import YAML from 'yaml';
import { addSourceEntry, channelFromClientName } from './sources.ts';

const D = '2026-10-06';
const parse = (y: string) => YAML.parse(y) as any;

describe('addSourceEntry', () => {
  test('sources al final: agrega y sigue siendo YAML válido', () => {
    const y = addSourceEntry('title: x\nsources:\n  - date: 2026-10-05\n    channel: claude-ai-web\n    session_id: abc', 'chatgpt-app', D);
    const d = parse(y);
    expect(d.sources.length).toBe(2);
    expect(d.sources[1].channel).toBe('chatgpt-app');
    expect(d.sources[1].stamped_by).toBe('wrapper');
  });

  // EL BUG: antes, esto producía YAML inválido
  test('sources ANTES de effective_date (orden R2→R6): no rompe nada', () => {
    const y = addSourceEntry('title: x\nsources:\n  - date: 2026-10-05\n    channel: claude-ai-web\n    session_id: abc\neffective_date: 2026-10-05', 'grok', D);
    const d = parse(y);
    expect(d.sources.length).toBe(2);
    expect(String(d.effective_date)).toContain('2026-10-05');
    expect(d.title).toBe('x');
  });

  test('sources en medio con varias claves detrás', () => {
    const d = parse(addSourceEntry('sources:\n  - date: 2026-10-05\n    channel: claude-ai-web\ntype: person\ntitle: Ana\ntags:\n  - a', 'cursor', D));
    expect(d.sources.map((s: any) => s.channel)).toEqual(['claude-ai-web', 'cursor']);
    expect(d.type).toBe('person'); expect(d.title).toBe('Ana'); expect(d.tags).toEqual(['a']);
  });

  test('lista con guiones en columna 0: respeta el estilo (mezclar sangrías rompe el YAML)', () => {
    const d = parse(addSourceEntry('sources:\n- date: 2026-10-05\n  channel: claude-ai-web\ntitle: x', 'grok', D));
    expect(d.sources.length).toBe(2); expect(d.title).toBe('x');
  });

  test('sin sources: lo crea al final', () => {
    const d = parse(addSourceEntry('title: x\ntype: person', 'cursor', D));
    expect(d.sources.length).toBe(1); expect(d.type).toBe('person');
  });

  test('frontmatter vacío', () => {
    expect(parse(addSourceEntry('', 'cursor', D)).sources.length).toBe(1);
  });

  test('sources: [] (vacío en línea) se convierte en lista de bloque', () => {
    const d = parse(addSourceEntry('title: x\nsources: []\ntype: person', 'cursor', D));
    expect(d.sources.length).toBe(1); expect(d.type).toBe('person');
  });

  test('el cliente YA puso ese canal: no duplica', () => {
    const y0 = 'title: x\nsources:\n  - date: 2026-10-06\n    channel: chatgpt-app\n    session_id: abc\neffective_date: 2026-10-06';
    expect(addSourceEntry(y0, 'chatgpt-app', D)).toBe(y0);
  });

  test('canal parecido pero distinto NO cuenta como duplicado', () => {
    const d = parse(addSourceEntry('sources:\n  - date: 2026-10-06\n    channel: chatgpt-app-old', 'chatgpt-app', D));
    expect(d.sources.length).toBe(2);
  });

  test('formato de una línea (flow): se deja intacto en vez de arriesgar corromperlo', () => {
    const y0 = 'title: x\nsources: [{date: "2026-10-06", channel: "claude-ai-web"}]\ntype: person';
    expect(addSourceEntry(y0, 'grok', D)).toBe(y0);
    expect(parse(y0).sources.length).toBe(1);
  });

  test('un canal con caracteres de regex no rompe la comparación', () => {
    expect(parse(addSourceEntry('sources:\n  - date: x\n    channel: a.b', 'a+b', D)).sources.length).toBe(2);
  });
});

describe('channelFromClientName', () => {
  test.each([
    ['Claude', 'claude-ai-web'], ['ChatGPT', 'chatgpt-app'], ['chatgpt-oauth', 'chatgpt-app'],
    ['grok', 'grok'], ['grok-v2', 'grok'], ['Grok Connectors', 'grok'], ['OpenAI Codex', 'chatgpt-app'],
  ])('%s → %s', (n, c) => expect(channelFromClientName(n)).toBe(c));
  test('desconocido / vacío → null (el llamador cae al comportamiento anterior)', () => {
    expect(channelFromClientName('smoke-test')).toBeNull();
    expect(channelFromClientName('')).toBeNull();
    expect(channelFromClientName(null)).toBeNull();
    expect(channelFromClientName(undefined)).toBeNull();
  });
});
