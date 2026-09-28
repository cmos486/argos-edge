// node:test suite for the pure filter vocabulary (no React, no DOM, no
// extra dev dependency): `npm run test:lib` compiles src/lib/filters.ts
// to .lib-test/ with tsc and runs this file with node --test.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  classifySearch,
  parseValues,
  pickRange,
  serializeValues,
} from '../../.lib-test/filters.js';

test('pickRange narrows to the page presets', () => {
  assert.equal(pickRange('7d', ['1h', '6h', '24h', '7d'], '24h'), '7d');
  assert.equal(pickRange('30d', ['1h', '6h', '24h', '7d'], '24h'), '24h');
  assert.equal(pickRange('junk', ['1h'], '1h'), '1h');
  assert.equal(pickRange(null, ['1h', '6h'], '6h'), '6h');
});

const schema = {
  range: { kind: 'range', allowed: ['1h', '6h', '24h', '7d'], default: '1h' },
  q: { kind: 'text' },
  source: { kind: 'enum', values: ['', 'caddy_access', 'caddy_error'], default: '' },
  offset: { kind: 'int', default: 0, min: 0 },
  regex: { kind: 'bool' },
};

test('parseValues applies defaults and validation', () => {
  const p = new URLSearchParams('range=7d&q=hello&source=nope&offset=-5&regex=1');
  const v = parseValues(schema, p);
  assert.equal(v.range, '7d');
  assert.equal(v.q, 'hello');
  assert.equal(v.source, '');
  assert.equal(v.offset, 0);
  assert.equal(v.regex, true);
  const empty = parseValues(schema, new URLSearchParams(''));
  assert.deepEqual(empty, { range: '1h', q: '', source: '', offset: 0, regex: false });
});

test('serializeValues round-trips and omits defaults', () => {
  const v = parseValues(schema, new URLSearchParams('range=6h&q=x&source=caddy_error&offset=100&regex=1'));
  const pairs = serializeValues(schema, v);
  assert.deepEqual(pairs, [
    ['range', '6h'],
    ['q', 'x'],
    ['source', 'caddy_error'],
    ['offset', '100'],
    ['regex', '1'],
  ]);
  const back = parseValues(schema, new URLSearchParams(pairs));
  assert.deepEqual(back, v);
  assert.deepEqual(serializeValues(schema, parseValues(schema, new URLSearchParams(''))), []);
});

test('classifySearch: ip, cidr, ipv6, domain, scenario, crs id, text', () => {
  assert.deepEqual(classifySearch(' 203.0.113.9 '), { kind: 'ip', value: '203.0.113.9' });
  assert.deepEqual(classifySearch('198.51.100.0/24'), { kind: 'ip', value: '198.51.100.0/24' });
  assert.deepEqual(classifySearch('2001:DB8::1'), { kind: 'ip', value: '2001:db8::1' });
  assert.deepEqual(classifySearch('Shop.Example.com'), { kind: 'domain', value: 'shop.example.com' });
  assert.deepEqual(classifySearch('crowdsecurity/http-probing'), { kind: 'scenario', value: 'crowdsecurity/http-probing' });
  assert.deepEqual(classifySearch('942100'), { kind: 'scenario', value: '942100' });
  assert.deepEqual(classifySearch('a:b'), { kind: 'text', value: 'a:b' });
  assert.deepEqual(classifySearch('login failed'), { kind: 'text', value: 'login failed' });
  assert.deepEqual(classifySearch(''), { kind: 'text', value: '' });
});
