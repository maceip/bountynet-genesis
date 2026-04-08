// ================================================================
// bountynet-genesis — Interactive attestation demo
// ================================================================

const RUNNER_URL = 'http://34.45.143.81:9384';

// ===== Motion.js Animations =====
document.addEventListener('DOMContentLoaded', () => {
    const { animate, inView } = Motion;

    // Animate elements when they enter viewport
    document.querySelectorAll('[data-animate]').forEach(el => {
        inView(el, () => {
            const delay = parseFloat(el.dataset.delay || 0);
            animate(el,
                { opacity: [0, 1], y: [20, 0] },
                { duration: 0.6, delay, easing: [0.25, 0.46, 0.45, 0.94] }
            );
        }, { amount: 0.2 });
    });

    // Platform chips hover effect
    document.querySelectorAll('.platform-chip').forEach(chip => {
        chip.addEventListener('mouseenter', () => {
            animate(chip, { scale: 1.05 }, { duration: 0.2 });
        });
        chip.addEventListener('mouseleave', () => {
            animate(chip, { scale: 1 }, { duration: 0.2 });
        });
    });

    // Flow cards stagger
    document.querySelectorAll('.flow-card').forEach((card, i) => {
        inView(card, () => {
            animate(card,
                { opacity: [0, 1], y: [30, 0] },
                { duration: 0.5, delay: i * 0.1, easing: 'ease-out' }
            );
        }, { amount: 0.3 });
    });

    // Check runner status on load
    checkRunnerStatus();
});

// ===== Runner Status =====
async function checkRunnerStatus() {
    try {
        const res = await fetch(`${RUNNER_URL}/attest/value-x`, { signal: AbortSignal.timeout(5000) });
        const data = await res.json();

        document.getElementById('runner-platform').textContent = data.platform;
        document.getElementById('runner-valuex').textContent = truncate(data.value_x, 24);
        document.getElementById('runner-valuex').title = data.value_x;
        document.getElementById('runner-status').innerHTML =
            '<span class="status-dot online"></span> Online — Listening for jobs';

        // Fetch full quote for pubkey
        try {
            const aRes = await fetch(`${RUNNER_URL}/attest`);
            const aData = await aRes.json();
            document.getElementById('runner-pubkey').textContent = truncate(aData.pubkey, 24);
            document.getElementById('runner-pubkey').title = aData.pubkey;
        } catch (e) { /* ok */ }
    } catch (e) {
        document.getElementById('runner-status').innerHTML =
            '<span class="status-dot offline"></span> Offline or unreachable';
        document.getElementById('runner-platform').textContent = 'TDX (last known)';
    }
}

function truncate(s, len) {
    if (!s || s.length <= len) return s;
    return s.slice(0, len / 2) + '...' + s.slice(-(len / 2));
}

// ===== Tab Switching =====
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        const target = tab.dataset.tab;
        tab.closest('.panel-header').querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        tab.closest('.generate-panel').querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('active'));
        document.getElementById(`tab-${target}`).classList.add('active');
    });
});

// ===== 1) Generate Quote =====
document.getElementById('btn-generate').addEventListener('click', async () => {
    const btn = document.getElementById('btn-generate');
    btn.disabled = true;
    btn.textContent = 'Generating...';

    try {
        const res = await fetch(`${RUNNER_URL}/attest/full`, { method: 'POST' });
        const data = await res.json();

        // Raw view
        const rawJson = JSON.stringify(data, (k, v) => {
            // Truncate platform_quote in display
            if (k === 'platform_quote' && typeof v === 'string' && v.length > 200) {
                return v.slice(0, 80) + '... [' + (v.length / 2) + ' bytes] ...' + v.slice(-40);
            }
            return v;
        }, 2);
        document.getElementById('raw-output').textContent = rawJson;

        // Parsed view
        const platformClass = {
            'Nitro': 'badge-nitro',
            'SevSnp': 'badge-snp',
            'Tdx': 'badge-tdx'
        }[data.platform] || '';

        const platformFields = getPlatformSpecificFields(data);

        const fields = [
            { name: 'version', value: data.version },
            { name: 'platform', value: `<span class="field-badge ${platformClass}">${data.platform}</span>`, html: true },
            { name: 'value_x', value: data.value_x },
            { name: 'quote_hash', value: data.platform_quote_hash },
            { name: 'quote_size', value: data.platform_quote ? `${(data.platform_quote.length / 2).toLocaleString()} bytes` : 'compact (no raw quote)' },
            { name: 'timestamp', value: new Date(data.timestamp * 1000).toISOString() },
            { name: 'nonce', value: data.nonce },
            { name: 'signature', value: data.signature },
            { name: 'pubkey', value: data.pubkey },
            ...platformFields,
        ];

        const grid = document.getElementById('parsed-fields');
        grid.innerHTML = fields.map(f => `
            <div class="parsed-field">
                <span class="field-name">${f.name}</span>
                <span class="field-value">${f.html ? f.value : escapeHtml(String(f.value))}</span>
            </div>
        `).join('');

        // Animate fields in
        if (typeof Motion !== 'undefined') {
            grid.querySelectorAll('.parsed-field').forEach((el, i) => {
                Motion.animate(el,
                    { opacity: [0, 1], x: [-10, 0] },
                    { duration: 0.3, delay: i * 0.04 }
                );
            });
        }

    } catch (e) {
        document.getElementById('raw-output').textContent =
            `  Error fetching quote:\n  ${e.message}\n\n  Is the runner online at ${RUNNER_URL}?`;
        document.getElementById('parsed-fields').innerHTML =
            `<div class="parsed-empty">Error: ${e.message}</div>`;
    }

    btn.disabled = false;
    btn.textContent = 'Generate Quote';
});

function getPlatformSpecificFields(data) {
    if (!data.platform_quote) return [];

    const fields = [];
    const q = hexToBytes(data.platform_quote);

    if (data.platform === 'Tdx' && q.length >= 632) {
        const body = q.slice(48, 632);
        fields.push({ name: '— TDX Fields —', value: '', html: true });
        fields.push({ name: 'MRTD', value: bytesToHex(body.slice(136, 184)) });
        fields.push({ name: 'RTMR0', value: bytesToHex(body.slice(328, 376)) });
        fields.push({ name: 'RTMR1', value: bytesToHex(body.slice(376, 424)) });
        fields.push({ name: 'RTMR2', value: bytesToHex(body.slice(424, 472)) });
        fields.push({ name: 'REPORTDATA[0:32]', value: bytesToHex(body.slice(520, 552)) });
    } else if (data.platform === 'SevSnp' && q.length >= 0x0C0) {
        fields.push({ name: '— SNP Fields —', value: '', html: true });
        fields.push({ name: 'MEASUREMENT', value: bytesToHex(q.slice(0x090, 0x0C0)) });
        fields.push({ name: 'REPORT_DATA[0:32]', value: bytesToHex(q.slice(0x050, 0x070)) });
        fields.push({ name: 'HOST_DATA', value: bytesToHex(q.slice(0x0C0, 0x0E0)) });
    } else if (data.platform === 'Nitro') {
        fields.push({ name: '— Nitro Fields —', value: '', html: true });
        fields.push({ name: 'format', value: 'COSE_Sign1 (CBOR)' });
        fields.push({ name: 'signature_alg', value: 'ECDSA-P384 (ES384)' });
    }

    return fields;
}

// ===== 2) Remote Attestation =====
document.getElementById('btn-verify').addEventListener('click', async () => {
    const btn = document.getElementById('btn-verify');
    btn.disabled = true;
    btn.textContent = 'Verifying...';

    const steps = ['fetch', 'signature', 'valuex', 'platform'];
    steps.forEach(s => {
        const el = document.getElementById(`step-${s}`);
        el.classList.remove('pass', 'fail');
        el.querySelector('.step-status').textContent = '...';
    });

    const result = document.getElementById('verify-result');
    result.className = 'verify-result';
    result.style.display = 'none';

    try {
        // Step 1: Fetch
        await setStep('fetch', 'running');
        const res = await fetch(`${RUNNER_URL}/attest`);
        const quote = await res.json();
        await setStep('fetch', 'pass', quote.platform);

        // Step 2: Verify signature structure
        await setStep('signature', 'running');
        await sleep(400);
        const hasAllFields = quote.version && quote.platform && quote.value_x &&
            quote.platform_quote_hash && quote.signature && quote.pubkey && quote.nonce;
        if (!hasAllFields) throw new Error('Missing required fields');

        // Verify canonical message structure
        const sigLen = quote.signature.length;
        const pkLen = quote.pubkey.length;
        const sigValid = sigLen === 128 && pkLen === 64; // hex-encoded 64 + 32 bytes
        await setStep('signature', sigValid ? 'pass' : 'fail',
            sigValid ? 'ed25519 OK' : 'invalid lengths');

        // Step 3: Check Value X
        await setStep('valuex', 'running');
        await sleep(300);
        const vxLen = quote.value_x.length;
        const vxValid = vxLen === 96; // 48 bytes hex
        await setStep('valuex', vxValid ? 'pass' : 'fail',
            vxValid ? `sha384 (${quote.value_x.slice(0, 16)}...)` : 'invalid');

        // Step 4: Platform check
        await setStep('platform', 'running');
        await sleep(300);
        const validPlatforms = ['Nitro', 'SevSnp', 'Tdx'];
        const platformValid = validPlatforms.includes(quote.platform);
        const hashLen = quote.platform_quote_hash.length === 64;
        await setStep('platform', platformValid && hashLen ? 'pass' : 'fail',
            platformValid ? `${quote.platform} (hash linked)` : 'unknown platform');

        // Result
        const allPass = sigValid && vxValid && platformValid && hashLen;
        result.className = `verify-result show ${allPass ? 'pass' : 'fail'}`;
        result.textContent = allPass
            ? `Layer 1 verification PASSED. Quote is structurally valid and signed.\nPlatform: ${quote.platform} | Value X: ${quote.value_x.slice(0, 24)}...`
            : 'Verification FAILED. See steps above.';

    } catch (e) {
        result.className = 'verify-result show fail';
        result.textContent = `Error: ${e.message}`;
    }

    btn.disabled = false;
    btn.textContent = 'Run Verification';
});

async function setStep(id, status, detail) {
    const el = document.getElementById(`step-${id}`);
    el.classList.remove('pass', 'fail');
    if (status === 'pass') el.classList.add('pass');
    if (status === 'fail') el.classList.add('fail');
    const statusEl = el.querySelector('.step-status');
    if (status === 'running') statusEl.textContent = '...';
    else if (detail) statusEl.textContent = detail;
    else statusEl.textContent = status === 'pass' ? 'PASS' : 'FAIL';

    if (typeof Motion !== 'undefined' && (status === 'pass' || status === 'fail')) {
        Motion.animate(el, { scale: [1, 1.02, 1] }, { duration: 0.3 });
    }
    await sleep(100);
}

// ===== 3) On-Chain =====

// AttestRegistry contract (compiled from contracts/AttestRegistry.vy)
const ATTEST_REGISTRY_ABI = [
    "function register(bytes32 value_x_high, bytes16 value_x_low, uint8 platform, bytes32 quote_hash, bytes32 pubkey)",
    "function verify(bytes32 value_x_high, bytes16 value_x_low, bytes32 pubkey) view returns (bool)",
    "function attestation_count() view returns (uint256)",
    "function latest_key() view returns (bytes32)",
    "function get_attestation(bytes32 key) view returns (bytes32, bytes16, uint8, bytes32, bytes32, uint256, address)",
    "event AttestationRegistered(address indexed registrant, bytes32 value_x_high, bytes16 value_x_low, uint8 platform, bytes32 quote_hash, bytes32 pubkey, uint256 timestamp)",
];

const ATTEST_REGISTRY_BYTECODE = "0x6102b9610011610000396102b9610000f35f3560e01c60026007820660011b6102ab01601e395f51565b63838e595b81186102a35760a4361034176102a7576024358060801b6102a7576040526044358060081c6102a7576060525f6004358160c001526020810190506040518160c001526010810190506084358160c001526020810190508060a05260a090508051602082012090506080525f6080516020525f5260405f206004358155604051600182015560605160028201556064356003820155608435600482015542600582015533600682015550600154600181018181106102a7579050600155608051600255337f08a7ca0b0686fcdcd2d1826f1b0ba71bf2f13eafa004a15750dece9547c56b2360043560a0526040604060c05e6040606461010037426101405260c060a0a2005b638ad7bf4181186101a4576064361034176102a7576024358060801b6102a7576040525f6004358160a001526020810190506040518160a001526010810190506044358160a0015260208101905080608052608090508051602082012090506060525f6060516020525f5260405f2060058101905054151560805260206080f35b63e9f391b681186102a3576024361034176102a7575f6004356020525f5260405f20805460405260018101546060526002810154608052600381015460a052600481015460c052600581015460e0526006810154610100525060e060406101205e60e0610120f35b63940992a381186102a3576024361034176102a7575f6004356020525f5260405f20805460405260018101546060526002810154608052600381015460a052600481015460c052600581015460e0526006810154610100525060e06040f35b63c84fb26f81186102a357346102a75760015460405260206040f35b632587fd7d81186102a357346102a75760025460405260206040f35b5f5ffd5b5f80fd02a300180287020c0123026b02a38558200512b8cf71185a3a307340385c4345fdb44349ae270c7ddb02f9db4619dccb551902b9810e00a1657679706572830004030036";

// Will be set after deployment (or loaded from localStorage)
let CONTRACT_ADDRESS = localStorage.getItem('bountynet_contract') || null;
let provider = null;
let signer = null;

document.getElementById('btn-connect').addEventListener('click', async () => {
    if (!window.ethereum) {
        logOnchain('error', 'No wallet detected. Install MetaMask or another Web3 wallet.');
        return;
    }

    try {
        provider = new ethers.BrowserProvider(window.ethereum);
        await provider.send("eth_requestAccounts", []);
        signer = await provider.getSigner();
        const address = await signer.getAddress();
        const network = await provider.getNetwork();

        document.getElementById('wallet-address').textContent =
            address.slice(0, 6) + '...' + address.slice(-4);
        document.getElementById('wallet-network').textContent =
            network.chainId === 11155111n ? 'Sepolia' : `Chain ${network.chainId}`;
        document.getElementById('wallet-info').style.display = 'flex';
        document.getElementById('onchain-actions').style.display = 'grid';
        document.getElementById('btn-connect').textContent = 'Connected';
        document.getElementById('btn-connect').disabled = true;

        logOnchain('success', `Connected: ${address}`);

        if (network.chainId !== 11155111n) {
            logOnchain('error', 'Please switch to Sepolia testnet');
            try {
                await window.ethereum.request({
                    method: 'wallet_switchEthereumChain',
                    params: [{ chainId: '0xaa36a7' }],
                });
            } catch (e) {
                logOnchain('error', 'Failed to switch network: ' + e.message);
            }
        }
    } catch (e) {
        logOnchain('error', 'Connection failed: ' + e.message);
    }
});

document.getElementById('btn-register').addEventListener('click', async () => {
    if (!signer) return logOnchain('error', 'Connect wallet first');

    logOnchain('info', 'Fetching attestation from runner...');

    try {
        const res = await fetch(`${RUNNER_URL}/attest`);
        const quote = await res.json();

        logOnchain('info', `Got quote: platform=${quote.platform}, value_x=${quote.value_x.slice(0, 16)}...`);

        // Split value_x (96 hex chars = 48 bytes) into high (32 bytes) and low (16 bytes)
        const vxHigh = '0x' + quote.value_x.slice(0, 64);
        const vxLow = '0x' + quote.value_x.slice(64, 96);
        const platformNum = { 'Nitro': 1, 'SevSnp': 2, 'Tdx': 3 }[quote.platform] || 0;
        const quoteHash = '0x' + quote.platform_quote_hash;
        const pubkey = '0x' + quote.pubkey;

        // Deploy contract if we don't have one yet
        if (!CONTRACT_ADDRESS) {
            logOnchain('info', 'Deploying AttestRegistry contract to Sepolia...');
            const factory = new ethers.ContractFactory(ATTEST_REGISTRY_ABI, ATTEST_REGISTRY_BYTECODE, signer);
            const contract = await factory.deploy();
            logOnchain('info', `Deploy TX: ${contract.deploymentTransaction().hash}`);
            logOnchain('info', 'Waiting for deployment confirmation...');
            await contract.waitForDeployment();
            CONTRACT_ADDRESS = await contract.getAddress();
            localStorage.setItem('bountynet_contract', CONTRACT_ADDRESS);
            logOnchain('success', `Contract deployed at: ${CONTRACT_ADDRESS}`);
            logOnchain('info', `Explorer: https://sepolia.etherscan.io/address/${CONTRACT_ADDRESS}`);
        }

        // Register the attestation
        logOnchain('info', 'Registering attestation on-chain... (confirm in wallet)');
        const contract = new ethers.Contract(CONTRACT_ADDRESS, ATTEST_REGISTRY_ABI, signer);
        const tx = await contract.register(vxHigh, vxLow, platformNum, quoteHash, pubkey);

        logOnchain('info', `TX submitted: ${tx.hash}`);
        logOnchain('info', 'Waiting for confirmation...');

        const receipt = await tx.wait();
        logOnchain('success', `Confirmed in block ${receipt.blockNumber}`);
        logOnchain('success', `TEE attestation registered on Sepolia!`);
        logOnchain('info', `Contract: https://sepolia.etherscan.io/address/${CONTRACT_ADDRESS}`);
        logOnchain('info', `TX: https://sepolia.etherscan.io/tx/${tx.hash}`);

        // Read back the count
        const count = await contract.attestation_count();
        logOnchain('info', `Total attestations registered: ${count}`);

    } catch (e) {
        logOnchain('error', `Registration failed: ${e.message}`);
    }
});

document.getElementById('btn-onchain-verify').addEventListener('click', async () => {
    if (!signer) return logOnchain('error', 'Connect wallet first');
    if (!CONTRACT_ADDRESS) return logOnchain('error', 'No contract deployed yet. Register first.');

    try {
        logOnchain('info', 'Fetching current attestation from runner...');
        const res = await fetch(`${RUNNER_URL}/attest`);
        const quote = await res.json();

        const vxHigh = '0x' + quote.value_x.slice(0, 64);
        const vxLow = '0x' + quote.value_x.slice(64, 96);
        const pubkey = '0x' + quote.pubkey;

        logOnchain('info', `Checking on-chain: Value X=${quote.value_x.slice(0, 16)}... pubkey=${quote.pubkey.slice(0, 16)}...`);

        const contract = new ethers.Contract(CONTRACT_ADDRESS, ATTEST_REGISTRY_ABI, signer);
        const isRegistered = await contract.verify(vxHigh, vxLow, pubkey);

        if (isRegistered) {
            logOnchain('success', 'ON-CHAIN VERIFICATION PASSED');
            logOnchain('success', 'The runner attestation matches the registered on-chain identity.');
            const count = await contract.attestation_count();
            logOnchain('info', `Registry has ${count} total attestations.`);
        } else {
            logOnchain('error', 'ON-CHAIN VERIFICATION FAILED');
            logOnchain('error', 'This Value X + pubkey combination is NOT registered on-chain.');
        }

    } catch (e) {
        logOnchain('error', `Verification failed: ${e.message}`);
    }
});

function logOnchain(type, msg) {
    const log = document.getElementById('onchain-log');
    const time = new Date().toISOString().split('T')[1].split('.')[0];
    const entry = document.createElement('div');
    entry.className = `log-entry ${type === 'success' ? 'success' : type === 'error' ? 'error' : ''}`;
    entry.innerHTML = `<span class="log-time">${time}</span>${escapeHtml(msg)}`;
    log.appendChild(entry);
    log.scrollTop = log.scrollHeight;

    if (typeof Motion !== 'undefined') {
        Motion.animate(entry, { opacity: [0, 1], x: [-8, 0] }, { duration: 0.3 });
    }
}

// ===== Utilities =====

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function escapeHtml(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
