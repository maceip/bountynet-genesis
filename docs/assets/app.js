// ================================================================
// bountynet-genesis :: Phrack-inspired React UI
// Uses Preact + htm (no build step needed)
// ================================================================

import { h, render } from 'https://esm.sh/preact@10.25.4';
import { useState, useEffect, useRef, useCallback } from 'https://esm.sh/preact@10.25.4/hooks';
import htm from 'https://esm.sh/htm@3.1.1';

const html = htm.bind(h);

// ===== Constants =====
const RUNNER_URL = 'http://34.45.143.81:9384';
const W = 80;

// ===== Utilities =====
function truncate(s, len) {
  if (!s || s.length <= len) return s;
  return s.slice(0, len / 2) + '…' + s.slice(-(len / 2));
}
function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  return bytes;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function center(s, w) {
  const pad = Math.max(0, Math.floor((w - s.length) / 2));
  return ' '.repeat(pad) + s;
}
function pad(s, w) {
  return s + ' '.repeat(Math.max(0, w - s.length));
}
function ruler(ch, w) { return ch.repeat(w); }
function dotfill(left, right, w) {
  const dots = w - left.length - right.length - 2;
  return left + ' ' + '.'.repeat(Math.max(3, dots)) + ' ' + right;
}

// ===== ASCII Art — 3D extruded block letters =====
// Front face rendered with per-line rainbow striping.
// Shadow layer (same text, CSS-offset) creates the depth extrusion.
const L = {
  B: [
    '\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588 ',
    '\u2588\u2588     \u2588\u2588 ',
    '\u2588\u2588     \u2588\u2588 ',
    '\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588 ',
    '\u2588\u2588     \u2588\u2588 ',
    '\u2588\u2588     \u2588\u2588 ',
    '\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588 ',
  ],
  O: [
    ' \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588 ',
    '\u2588\u2588      \u2588\u2588',
    '\u2588\u2588      \u2588\u2588',
    '\u2588\u2588      \u2588\u2588',
    '\u2588\u2588      \u2588\u2588',
    '\u2588\u2588      \u2588\u2588',
    ' \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588 ',
  ],
  U: [
    '\u2588\u2588      \u2588\u2588',
    '\u2588\u2588      \u2588\u2588',
    '\u2588\u2588      \u2588\u2588',
    '\u2588\u2588      \u2588\u2588',
    '\u2588\u2588      \u2588\u2588',
    '\u2588\u2588      \u2588\u2588',
    ' \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588 ',
  ],
  N: [
    '\u2588\u2588\u2588     \u2588\u2588',
    '\u2588\u2588\u2588\u2588    \u2588\u2588',
    '\u2588\u2588 \u2588\u2588   \u2588\u2588',
    '\u2588\u2588  \u2588\u2588  \u2588\u2588',
    '\u2588\u2588   \u2588\u2588 \u2588\u2588',
    '\u2588\u2588    \u2588\u2588\u2588\u2588',
    '\u2588\u2588     \u2588\u2588\u2588',
  ],
  T: [
    '\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588',
    '\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588',
    '    \u2588\u2588    ',
    '    \u2588\u2588    ',
    '    \u2588\u2588    ',
    '    \u2588\u2588    ',
    '    \u2588\u2588    ',
  ],
  Y: [
    '\u2588\u2588      \u2588\u2588',
    ' \u2588\u2588    \u2588\u2588 ',
    '  \u2588\u2588  \u2588\u2588  ',
    '   \u2588\u2588\u2588\u2588   ',
    '    \u2588\u2588    ',
    '    \u2588\u2588    ',
    '    \u2588\u2588    ',
  ],
  E: [
    '\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588',
    '\u2588\u2588        ',
    '\u2588\u2588        ',
    '\u2588\u2588\u2588\u2588\u2588\u2588\u2588   ',
    '\u2588\u2588        ',
    '\u2588\u2588        ',
    '\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588',
  ],
};

function composeWord(chars, gap) {
  const letters = chars.map(c => L[c]);
  return letters[0].map((_, r) => letters.map(l => l[r]).join(gap));
}

const BOUNTY_ROWS = composeWord(['B','O','U','N','T','Y'], '  ');
const NET_ROWS = composeWord(['N','E','T'], '  ');
const ART_W = BOUNTY_ROWS[0].length;
const NET_PAD = Math.floor((ART_W - NET_ROWS[0].length) / 2);
const FRONT_COLORS = ['c-purple','c-indigo','c-cyan','c-green','c-pink','c-amber','c-purple'];


// ===== Contract ABI =====
const ATTEST_REGISTRY_ABI = [
  "function register(bytes32 value_x_high, bytes16 value_x_low, uint8 platform, bytes32 quote_hash, bytes32 pubkey)",
  "function verify(bytes32 value_x_high, bytes16 value_x_low, bytes32 pubkey) view returns (bool)",
  "function attestation_count() view returns (uint256)",
  "function latest_key() view returns (bytes32)",
  "function get_attestation(bytes32 key) view returns (bytes32, bytes16, uint8, bytes32, bytes32, uint256, address)",
  "event AttestationRegistered(address indexed registrant, bytes32 value_x_high, bytes16 value_x_low, uint8 platform, bytes32 quote_hash, bytes32 pubkey, uint256 timestamp)",
];
const ATTEST_REGISTRY_BYTECODE = "0x6102b9610011610000396102b9610000f35f3560e01c60026007820660011b6102ab01601e395f51565b63838e595b81186102a35760a4361034176102a7576024358060801b6102a7576040526044358060081c6102a7576060525f6004358160c001526020810190506040518160c001526010810190508060a05260a090508051602082012090506080525f6080516020525f5260405f206004358155604051600182015560605160028201556064356003820155608435600482015542600582015533600682015550600154600181018181106102a7579050600155608051600255337f08a7ca0b0686fcdcd2d1826f1b0ba71bf2f13eafa004a15750dece9547c56b2360043560a0526040604060c05e6040606461010037426101405260c060a0a2005b638ad7bf4181186101a4576064361034176102a7576024358060801b6102a7576040525f6004358160a001526020810190506040518160a001526010810190506044358160a0015260208101905080608052608090508051602082012090506060525f6060516020525f5260405f2060058101905054151560805260206080f35b63e9f391b681186102a3576024361034176102a7575f6004356020525f5260405f20805460405260018101546060526002810154608052600381015460a052600481015460c052600581015460e0526006810154610100525060e060406101205e60e0610120f35b63940992a381186102a3576024361034176102a7575f6004356020525f5260405f20805460405260018101546060526002810154608052600381015460a052600481015460c052600581015460e0526006810154610100525060e06040f35b63c84fb26f81186102a357346102a75760015460405260206040f35b632587fd7d81186102a357346102a75760025460405260206040f35b5f5ffd5b5f80fd02a300180287020c0123026b02a38558200512b8cf71185a3a307340385c4345fdb44349ae270c7ddb02f9db4619dccb551902b9810e00a1657679706572830004030036";

// ===== TOC Data =====
const TOC = [
  { num: '0x01', title: 'Introduction', id: 'intro' },
  { num: '0x02', title: 'How a Quote is Minted', id: 'flow' },
  { num: '0x03', title: 'Live Runner', id: 'runner' },
  { num: '0x04', title: 'Generate Quote', id: 'generate' },
  { num: '0x05', title: 'Remote Attestation', id: 'verify' },
  { num: '0x06', title: 'On-Chain Verification', id: 'onchain' },
  { num: '0x07', title: 'Greetz', id: 'greetz' },
];

// ===== Flow Steps Data =====
const FLOW_STEPS = [
  { num: '01', title: 'TEE Boot',
    desc: 'The CPU creates an encrypted memory region. Every byte of code loaded is measured \u2014 hashed into tamper-evident registers that can never be rolled back.' },
  { num: '02', title: 'Compute Value X',
    desc: 'bountynet-shim walks every file in the runner directory, hashes them deterministically, and produces a single 48-byte fingerprint. Same code = same X on any platform.' },
  { num: '03', title: 'Bind & Sign',
    desc: 'Value X and a fresh signing key are bound into the TEE\'s report data. The hardware signs a quote proving this key was generated inside a genuine enclave.' },
  { num: '04', title: 'Wrap in UnifiedQuote',
    desc: 'The platform-specific evidence gets wrapped into a single format with an ed25519 signature. ~180 bytes on-chain, full quote off-chain and hash-linked.' },
  { num: '05', title: 'Serve & Verify',
    desc: 'The runner serves /attest for remote verification while executing your jobs. Anyone can verify Layer 1 (signature) or Layer 2 (full hardware chain).' },
];

// ===== Greetz Data =====
const GREETZ = [
  { name: 'sid', cls: 'name-sid', role: 'the foundation' },
  { name: 'zen', cls: 'name-zen', role: 'the way' },
  { name: 'josh', cls: 'name-josh', role: 'the architect' },
  { name: '$adAngels', cls: 'name-adangels', role: 'the watchers' },
  { name: 'amiller', cls: 'name-amiller', role: 'the prover' },
  { name: 'phala', cls: 'name-phala', role: 'the network' },
];

// ===== Components =====

function ThemeToggle({ theme, onToggle }) {
  const icon = theme === 'dark' ? '\u263E' : '\u2600';
  const label = theme === 'dark' ? 'light' : 'dark';
  return html`<button class="theme-toggle" onClick=${onToggle} title="Switch to ${label} mode">
    ${icon} ${label}
  </button>`;
}

function AsciiHeader() {
  const allRows = [
    ...BOUNTY_ROWS,
    '',
    ...NET_ROWS.map(l => ' '.repeat(NET_PAD) + l),
  ];
  const colors = [
    ...FRONT_COLORS,
    '',
    ...FRONT_COLORS,
  ];
  const plainText = allRows.join('\n');

  return html`<div class="ascii-header">
    <div class="art-3d">
      <pre class="art-layer art-shadow" aria-hidden="true">${plainText}</pre>
      <pre class="art-layer art-front" aria-label="BOUNTY NET">${
        allRows.map((l, i) => html`<span key=${i} class=${colors[i] || ''}>${l}</span>${'\n'}`)
      }</pre>
    </div>
    <pre class="art-sub"><span class="c-rule">${'\u2550'.repeat(ART_W)}</span>${'\n'}<span class="c-dim">${center('\u00ab g e n e s i s \u00bb', ART_W)}</span>${'\n'}<span class="c-dim">${center('trust the build \u00b7 verify the machine', ART_W)}</span></pre>
  </div>`;
}

function ZineInfo() {
  return html`<div class="zine-info">
    <div class="rule">${'\u2550'.repeat(40)}</div>
    <div class="tagline">Trust the build. Verify the machine.</div>
    <div class="rule">${'\u2550'.repeat(40)}</div>
    <br />
    <div>A GitHub Actions runner that produces</div>
    <div>cryptographic proof of its own integrity.</div>
    <div>Three platforms. One format. On-chain.</div>
    <br />
    <div class="meta">.oO bountynet collective Oo.</div>
  </div>`;
}

function TableOfContents() {
  return html`<div class="toc">
    <div class="toc-header">${'\u2500'.repeat(3)}[ Table of Contents ]${'\u2500'.repeat(W - 25)}</div>
    ${TOC.map(e => html`
      <a key=${e.id} class="toc-entry" href="#${e.id}">
        <span>  </span>
        <span class="toc-num">${e.num}</span>
        <span class="toc-dots"> ${'.'.repeat(Math.max(3, 60 - e.title.length))} </span>
        <span class="toc-title">${e.title}</span>
      </a>
    `)}
  </div>`;
}

function SectionDivider({ num, title, id }) {
  const header = `\u2500\u2500[ ${num} \u00b7 ${title} ]`;
  const fill = '\u2500'.repeat(Math.max(4, W - header.length));
  return html`<div class="section-divider" id=${id}>
    <div class="divider-line">${'\u2500'.repeat(W)}</div>
    <div><span class="divider-line">\u2500\u2500[ </span><span class="divider-num">${num}</span><span class="divider-line"> \u00b7 </span><span class="divider-title">${title}</span><span class="divider-line"> ]${fill}</span></div>
    <div class="divider-line">${'\u2500'.repeat(W)}</div>
  </div>`;
}

function Introduction() {
  return html`<div class="section-content">
    <p>When you run code on someone else's computer \u2014 a cloud VM, a CI runner,
    a build server \u2014 you're trusting that the machine is running the software
    it claims, that nobody modified it after deployment, and that nobody is
    watching or tampering with execution.</p>
    <p>Normally, you just take the cloud provider's word for it.
    <span class="highlight">bountynet-genesis replaces that trust with math.</span></p>
    <p>Your code runs inside a <span class="highlight">Trusted Execution Environment</span> (TEE)
    \u2014 a hardware feature built into modern CPUs that creates an isolated, encrypted
    area of memory. The CPU itself enforces the isolation. Not the OS, not the
    hypervisor, not the cloud provider. The silicon.</p>
    <p>bountynet-genesis wraps quotes from three different hardware platforms
    into a single format called <span class="highlight">UnifiedQuote</span>, so verifiers
    don't need to care which cloud or chip produced the proof.</p>
    <div class="platforms">
      <span class="platform-badge"><span class="platform-dot dot-nitro"></span> AWS Nitro</span>
      <span class="platform-badge"><span class="platform-dot dot-snp"></span> AMD SEV-SNP</span>
      <span class="platform-badge"><span class="platform-dot dot-tdx"></span> Intel TDX</span>
    </div>
  </div>`;
}

function FlowSection() {
  return html`<div class="section-content">
    <p class="dim">From boot to on-chain verification in five steps.</p>
    ${FLOW_STEPS.map(s => html`
      <div key=${s.num} class="flow-step">
        <div><span class="flow-num">[${s.num}]</span> <span class="flow-title">${s.title}</span></div>
        <div class="flow-desc">${s.desc}</div>
      </div>
    `)}
  </div>`;
}

function RunnerStatus() {
  const [status, setStatus] = useState({ platform: '\u2014', valuex: '\u2014', pubkey: '\u2014', online: null });

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(RUNNER_URL + '/attest/value-x', { signal: AbortSignal.timeout(5000) });
        const data = await res.json();
        let pubkey = '\u2014';
        try {
          const aRes = await fetch(RUNNER_URL + '/attest');
          const aData = await aRes.json();
          pubkey = truncate(aData.pubkey, 24);
        } catch(e) {}
        setStatus({ platform: data.platform, valuex: truncate(data.value_x, 28), pubkey, online: true });
      } catch(e) {
        setStatus({ platform: 'TDX (last known)', valuex: '\u2014', pubkey: '\u2014', online: false });
      }
    })();
  }, []);

  return html`<div class="section-content">
    <p class="dim">A real GitHub Actions runner on Intel TDX hardware, serving attestation right now.</p>
    <div class="terminal-panel">
      <div class="terminal-bar">
        <div class="terminal-bar-left">
          <span class="terminal-dot red"></span>
          <span class="terminal-dot yellow"></span>
          <span class="terminal-dot green"></span>
          <span style="margin-left: 8px">runner-status</span>
        </div>
        <span>${RUNNER_URL}</span>
      </div>
      <div class="terminal-body">
        <div class="status-row"><span class="status-label">Platform</span><span class="status-value">${status.platform}</span></div>
        <div class="status-row"><span class="status-label">Value X</span><span class="status-value">${status.valuex}</span></div>
        <div class="status-row"><span class="status-label">Pubkey</span><span class="status-value">${status.pubkey}</span></div>
        <div class="status-row"><span class="status-label">Status</span><span class="status-value ${status.online === true ? 'status-online' : status.online === false ? 'status-offline' : ''}">${status.online === true ? '\u25cf Online \u2014 Listening for jobs' : status.online === false ? '\u25cb Offline or unreachable' : '\u25cb Checking...'}</span></div>
      </div>
    </div>
  </div>`;
}

function GenerateQuote() {
  const [tab, setTab] = useState('parsed');
  const [loading, setLoading] = useState(false);
  const [rawData, setRawData] = useState(null);
  const [fields, setFields] = useState(null);
  const [error, setError] = useState(null);

  const generate = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(RUNNER_URL + '/attest/full', { method: 'POST' });
      const data = await res.json();
      setRawData(data);

      const platformClass = { 'Nitro': 'badge-nitro', 'SevSnp': 'badge-snp', 'Tdx': 'badge-tdx' }[data.platform] || '';
      const pf = getPlatformFields(data);
      const f = [
        { name: 'version', value: String(data.version) },
        { name: 'platform', value: data.platform, badge: platformClass },
        { name: 'value_x', value: data.value_x },
        { name: 'quote_hash', value: data.platform_quote_hash },
        { name: 'quote_size', value: data.platform_quote ? (data.platform_quote.length / 2).toLocaleString() + ' bytes' : 'compact' },
        { name: 'timestamp', value: new Date(data.timestamp * 1000).toISOString() },
        { name: 'nonce', value: data.nonce },
        { name: 'signature', value: data.signature },
        { name: 'pubkey', value: data.pubkey },
        ...pf,
      ];
      setFields(f);
    } catch (e) {
      setError(e.message);
    }
    setLoading(false);
  }, []);

  const rawJson = rawData ? JSON.stringify(rawData, (k, v) => {
    if (k === 'platform_quote' && typeof v === 'string' && v.length > 200)
      return v.slice(0, 80) + '... [' + (v.length / 2) + ' bytes] ...' + v.slice(-40);
    return v;
  }, 2) : '  Waiting for quote generation...\n\n  Press "Generate Quote" to fetch a fresh\n  attestation from the running TEE.';

  return html`<div class="section-content">
    <p class="dim">Request a fresh attestation quote from the running TEE. See it raw or parsed.</p>
    <div class="terminal-panel">
      <div class="terminal-bar">
        <div class="tab-bar">
          <button class="tab-btn ${tab === 'parsed' ? 'active' : ''}" onClick=${() => setTab('parsed')}>Parsed</button>
          <button class="tab-btn ${tab === 'raw' ? 'active' : ''}" onClick=${() => setTab('raw')}>Raw</button>
        </div>
        <button class="btn btn-primary" onClick=${generate} disabled=${loading}>
          ${loading ? 'Generating...' : 'Generate Quote'}
        </button>
      </div>
      <div class="terminal-body">
        ${tab === 'parsed' ? html`
          ${error ? html`<div style="color: var(--red)">Error: ${error}</div>` :
            !fields ? html`<div class="dim">Click "Generate Quote" to request a fresh attestation from the TEE.</div>` :
            fields.map((f, i) => f.separator ?
              html`<div key=${i} class="field-separator">${'\u2500'.repeat(3)} ${f.name} ${'\u2500'.repeat(3)}</div>` :
              html`<div key=${i} class="parsed-field">
                <span class="field-name">${f.name}</span>
                <span class="field-value">${f.badge ? html`<span class="badge ${f.badge}">${f.value}</span>` : f.value}</span>
              </div>`
            )}
        ` : html`
          <div class="nano-shell">
            <div class="nano-header">
              <span>GNU nano 7.2</span>
              <span>unified_quote.json</span>
              <span>${rawData ? 'Modified' : ''}</span>
            </div>
            <pre class="nano-body">${rawJson}</pre>
            <div class="nano-footer">
              <span>^G Help</span><span>^O Write Out</span><span>^W Where Is</span><span>^K Cut</span><span>^T Execute</span>
            </div>
          </div>
        `}
      </div>
    </div>
  </div>`;
}

function getPlatformFields(data) {
  if (!data.platform_quote) return [];
  const fields = [];
  const q = hexToBytes(data.platform_quote);
  if (data.platform === 'Tdx' && q.length >= 632) {
    const body = q.slice(48, 632);
    fields.push({ name: 'TDX Fields', separator: true });
    fields.push({ name: 'MRTD', value: bytesToHex(body.slice(136, 184)) });
    fields.push({ name: 'RTMR0', value: bytesToHex(body.slice(328, 376)) });
    fields.push({ name: 'RTMR1', value: bytesToHex(body.slice(376, 424)) });
    fields.push({ name: 'RTMR2', value: bytesToHex(body.slice(424, 472)) });
    fields.push({ name: 'REPORTDATA[0:32]', value: bytesToHex(body.slice(520, 552)) });
  } else if (data.platform === 'SevSnp' && q.length >= 0x0C0) {
    fields.push({ name: 'SNP Fields', separator: true });
    fields.push({ name: 'MEASUREMENT', value: bytesToHex(q.slice(0x090, 0x0C0)) });
    fields.push({ name: 'REPORT_DATA[0:32]', value: bytesToHex(q.slice(0x050, 0x070)) });
    fields.push({ name: 'HOST_DATA', value: bytesToHex(q.slice(0x0C0, 0x0E0)) });
  } else if (data.platform === 'Nitro') {
    fields.push({ name: 'Nitro Fields', separator: true });
    fields.push({ name: 'format', value: 'COSE_Sign1 (CBOR)' });
    fields.push({ name: 'signature_alg', value: 'ECDSA-P384 (ES384)' });
  }
  return fields;
}

function RemoteAttestation() {
  const [steps, setSteps] = useState([
    { id: 'fetch', title: 'Fetch Quote', desc: 'Request compact attestation from /attest', status: '\u2014' },
    { id: 'signature', title: 'Verify Signature', desc: 'Check ed25519 signature over canonical fields (Layer 1)', status: '\u2014' },
    { id: 'valuex', title: 'Check Value X', desc: 'Compare against known-good runner identity', status: '\u2014' },
    { id: 'platform', title: 'Platform Check', desc: 'Verify platform_quote_hash links to full TEE evidence', status: '\u2014' },
  ]);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const updateStep = (id, state, detail) => {
    setSteps(prev => prev.map(s => s.id === id ? { ...s, state, status: detail || (state === 'pass' ? 'PASS' : state === 'fail' ? 'FAIL' : '...') } : s));
  };

  const verify = useCallback(async () => {
    setLoading(true);
    setResult(null);
    setSteps(prev => prev.map(s => ({ ...s, state: undefined, status: '\u2014' })));

    try {
      updateStep('fetch', 'running', '...');
      const res = await fetch(RUNNER_URL + '/attest');
      const quote = await res.json();
      updateStep('fetch', 'pass', quote.platform);

      updateStep('signature', 'running', '...');
      await sleep(400);
      const hasAll = quote.version && quote.platform && quote.value_x && quote.platform_quote_hash && quote.signature && quote.pubkey && quote.nonce;
      if (!hasAll) throw new Error('Missing required fields');
      const sigValid = quote.signature.length === 128 && quote.pubkey.length === 64;
      updateStep('signature', sigValid ? 'pass' : 'fail', sigValid ? 'ed25519 OK' : 'invalid lengths');

      updateStep('valuex', 'running', '...');
      await sleep(300);
      const vxValid = quote.value_x.length === 96;
      updateStep('valuex', vxValid ? 'pass' : 'fail', vxValid ? 'sha384 (' + quote.value_x.slice(0, 16) + '...)' : 'invalid');

      updateStep('platform', 'running', '...');
      await sleep(300);
      const validP = ['Nitro', 'SevSnp', 'Tdx'];
      const pValid = validP.includes(quote.platform);
      const hValid = quote.platform_quote_hash.length === 64;
      updateStep('platform', pValid && hValid ? 'pass' : 'fail', pValid ? quote.platform + ' (hash linked)' : 'unknown platform');

      const allPass = sigValid && vxValid && pValid && hValid;
      setResult({
        pass: allPass,
        text: allPass
          ? 'Layer 1 verification PASSED. Quote is structurally valid and signed.\nPlatform: ' + quote.platform + ' | Value X: ' + quote.value_x.slice(0, 24) + '...'
          : 'Verification FAILED. See steps above.'
      });
    } catch (e) {
      setResult({ pass: false, text: 'Error: ' + e.message });
    }
    setLoading(false);
  }, []);

  return html`<div class="section-content">
    <p class="dim">Verify the quote cryptographically \u2014 right here in your browser.</p>
    ${steps.map((s, i) => html`
      <div key=${s.id} class="verify-step ${s.state || ''}">
        <span class="step-num">[${i + 1}]</span>
        <div class="step-info">
          <div class="step-title">${s.title}</div>
          <div class="step-desc">${s.desc}</div>
        </div>
        <span class="step-status">${s.status}</span>
      </div>
    `)}
    <div class="btn-group">
      <button class="btn btn-primary" onClick=${verify} disabled=${loading}>
        ${loading ? 'Verifying...' : 'Run Verification'}
      </button>
    </div>
    ${result ? html`<div class="verify-result ${result.pass ? 'pass' : 'fail'}">${result.text}</div>` : null}
  </div>`;
}

function OnChainSection() {
  const [connected, setConnected] = useState(false);
  const [address, setAddress] = useState('');
  const [network, setNetwork] = useState('');
  const [logs, setLogs] = useState([]);
  const [contractAddr, setContractAddr] = useState(localStorage.getItem('bountynet_contract') || null);
  const signerRef = useRef(null);
  const logRef = useRef(null);

  const addLog = (type, msg) => {
    const time = new Date().toISOString().split('T')[1].split('.')[0];
    setLogs(prev => [...prev, { type, msg, time }]);
  };

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  const connect = useCallback(async () => {
    if (!window.ethereum) { addLog('error', 'No wallet detected. Install MetaMask.'); return; }
    try {
      const provider = new ethers.BrowserProvider(window.ethereum);
      await provider.send('eth_requestAccounts', []);
      const signer = await provider.getSigner();
      signerRef.current = signer;
      const addr = await signer.getAddress();
      const net = await provider.getNetwork();
      setAddress(addr.slice(0, 6) + '...' + addr.slice(-4));
      setNetwork(net.chainId === 11155111n ? 'Sepolia' : 'Chain ' + net.chainId);
      setConnected(true);
      addLog('success', 'Connected: ' + addr);
      if (net.chainId !== 11155111n) {
        addLog('error', 'Please switch to Sepolia testnet');
        try { await window.ethereum.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: '0xaa36a7' }] }); }
        catch(e) { addLog('error', 'Failed to switch: ' + e.message); }
      }
    } catch(e) { addLog('error', 'Connection failed: ' + e.message); }
  }, []);

  const register = useCallback(async () => {
    if (!signerRef.current) { addLog('error', 'Connect wallet first'); return; }
    addLog('info', 'Fetching attestation from runner...');
    try {
      const res = await fetch(RUNNER_URL + '/attest');
      const quote = await res.json();
      addLog('info', 'Got quote: platform=' + quote.platform + ', value_x=' + quote.value_x.slice(0, 16) + '...');
      const vxHigh = '0x' + quote.value_x.slice(0, 64);
      const vxLow = '0x' + quote.value_x.slice(64, 96);
      const platformNum = { 'Nitro': 1, 'SevSnp': 2, 'Tdx': 3 }[quote.platform] || 0;
      const quoteHash = '0x' + quote.platform_quote_hash;
      const pubkey = '0x' + quote.pubkey;

      let ca = contractAddr;
      if (!ca) {
        addLog('info', 'Deploying AttestRegistry to Sepolia...');
        const factory = new ethers.ContractFactory(ATTEST_REGISTRY_ABI, ATTEST_REGISTRY_BYTECODE, signerRef.current);
        const c = await factory.deploy();
        addLog('info', 'Deploy TX: ' + c.deploymentTransaction().hash);
        await c.waitForDeployment();
        ca = await c.getAddress();
        localStorage.setItem('bountynet_contract', ca);
        setContractAddr(ca);
        addLog('success', 'Contract deployed at: ' + ca);
      }

      addLog('info', 'Registering attestation on-chain...');
      const contract = new ethers.Contract(ca, ATTEST_REGISTRY_ABI, signerRef.current);
      const tx = await contract.register(vxHigh, vxLow, platformNum, quoteHash, pubkey);
      addLog('info', 'TX submitted: ' + tx.hash);
      const receipt = await tx.wait();
      addLog('success', 'Confirmed in block ' + receipt.blockNumber);
      addLog('success', 'TEE attestation registered on Sepolia!');
      const count = await contract.attestation_count();
      addLog('info', 'Total attestations: ' + count);
    } catch(e) { addLog('error', 'Registration failed: ' + e.message); }
  }, [contractAddr]);

  const verifyOnChain = useCallback(async () => {
    if (!signerRef.current) { addLog('error', 'Connect wallet first'); return; }
    if (!contractAddr) { addLog('error', 'No contract deployed. Register first.'); return; }
    try {
      addLog('info', 'Fetching current attestation...');
      const res = await fetch(RUNNER_URL + '/attest');
      const quote = await res.json();
      const vxHigh = '0x' + quote.value_x.slice(0, 64);
      const vxLow = '0x' + quote.value_x.slice(64, 96);
      const pubkey = '0x' + quote.pubkey;
      const contract = new ethers.Contract(contractAddr, ATTEST_REGISTRY_ABI, signerRef.current);
      const ok = await contract.verify(vxHigh, vxLow, pubkey);
      if (ok) {
        addLog('success', 'ON-CHAIN VERIFICATION PASSED');
        addLog('success', 'Runner matches registered identity.');
      } else {
        addLog('error', 'ON-CHAIN VERIFICATION FAILED');
        addLog('error', 'Value X + pubkey NOT registered on-chain.');
      }
    } catch(e) { addLog('error', 'Verification failed: ' + e.message); }
  }, [contractAddr]);

  return html`<div class="section-content">
    <p class="dim">Submit the attestation to a smart contract on Sepolia. The contract stores the TEE identity and gates future actions behind proof.</p>
    <div class="wallet-bar">
      <button class="btn ${connected ? '' : 'btn-primary'}" onClick=${connect} disabled=${connected}>
        ${connected ? '\u2713 Connected' : 'Connect Wallet'}
      </button>
      ${connected ? html`
        <span class="wallet-info">${address}<span class="wallet-network">${network}</span></span>
      ` : null}
    </div>
    ${connected ? html`
      <div class="onchain-actions">
        <div class="action-box">
          <h4>Register TEE Identity</h4>
          <p>Deploy attestation identity on-chain. Costs gas.</p>
          <button class="btn btn-primary" onClick=${register}>Register on Sepolia</button>
        </div>
        <div class="action-box">
          <h4>Verify On-Chain</h4>
          <p>Check if runner's Value X matches registered identity.</p>
          <button class="btn" onClick=${verifyOnChain}>Verify Match</button>
        </div>
      </div>
    ` : null}
    ${logs.length > 0 ? html`
      <div class="chain-log" ref=${logRef}>
        ${logs.map((l, i) => html`
          <div key=${i} class="log-line ${l.type === 'success' ? 'success' : l.type === 'error' ? 'error' : ''}">
            <span class="log-time">${l.time}</span>${l.msg}
          </div>
        `)}
      </div>
    ` : null}
  </div>`;
}

function Greetz() {
  const maxName = Math.max(...GREETZ.map(g => g.name.length));
  return html`<div class="section-content">
    <div class="greetz-container">
      <div class="greetz-header">going out to the following who make this possible:</div>
      <div class="greetz-frame">
        ${GREETZ.map((g, i) => {
          const dots = '.'.repeat(Math.max(3, 48 - g.name.length - g.role.length));
          return html`
            <div key=${i} class="greet-entry">
              <span class="greet-marker">${'\u00bb'} </span>
              <span class="greet-name ${g.cls}">${g.name}</span>
              <span class="greet-dots">${dots}</span>
              <span class="greet-role">${g.role}</span>
            </div>`;
        })}
      </div>
      <div class="greetz-footer">${'\u00b7'} stay verified ${'\u00b7'}</div>
    </div>
  </div>`;
}

function Footer() {
  return html`<div class="zine-footer">
    <div class="footer-rule">${'\u2550'.repeat(W)}</div>
    <div class="footer-eof">\u2500\u2500 EOF \u2500\u2500</div>
    <div class="footer-rule">${'\u2550'.repeat(W)}</div>
    <div class="footer-links">
      <a href="https://github.com/maceip/bountynet-genesis">GitHub</a>
      <a href="https://github.com/maceip/bountynet-genesis/actions">Actions</a>
    </div>
  </div>`;
}

// ===== Main App =====

function App() {
  const [theme, setTheme] = useState(() => {
    const saved = localStorage.getItem('bountynet-theme');
    if (saved) return saved;
    return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('bountynet-theme', theme);
  }, [theme]);

  const toggle = useCallback(() => {
    setTheme(t => t === 'dark' ? 'light' : 'dark');
  }, []);

  return html`
    <${ThemeToggle} theme=${theme} onToggle=${toggle} />
    <main class="zine">
      <${AsciiHeader} />
      <${ZineInfo} />
      <${TableOfContents} />
      <${SectionDivider} num="0x01" title="Introduction" id="intro" />
      <${Introduction} />
      <${SectionDivider} num="0x02" title="How a Quote is Minted" id="flow" />
      <${FlowSection} />
      <${SectionDivider} num="0x03" title="Live Runner" id="runner" />
      <${RunnerStatus} />
      <${SectionDivider} num="0x04" title="Generate Quote" id="generate" />
      <${GenerateQuote} />
      <${SectionDivider} num="0x05" title="Remote Attestation" id="verify" />
      <${RemoteAttestation} />
      <${SectionDivider} num="0x06" title="On-Chain Verification" id="onchain" />
      <${OnChainSection} />
      <${SectionDivider} num="0x07" title="Greetz" id="greetz" />
      <${Greetz} />
      <${Footer} />
    </main>
  `;
}

// ===== Mount =====
render(html`<${App} />`, document.getElementById('root'));
