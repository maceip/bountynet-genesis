/* bountynet-genesis // live Value X verifier
 *
 * Pure browser JS. No build step. No backend. No WASM.
 * Walks the repo tree via the GitHub API, fetches every file raw, and
 * computes Value X exactly the way `bountynet` computes it on the TEE —
 * showing every step live in the DOM so a visitor can watch the
 * attestation root come into existence in front of them.
 *
 * Algorithm (must match v2/src/main.rs :: compute_tree_hash):
 *
 *   skip any path segment in {".git","target","node_modules",".DS_Store","out"}
 *   for each remaining blob:
 *       file_hash = sha384(raw_bytes)
 *   sort entries by path (byte-lex)
 *   Value X = sha384( for each entry: path || ":" || hex(file_hash) || "\n" )
 *
 * The file_hash printed below every row is a real sha384 the browser computed,
 * not a value fetched from the server. Open devtools if you want to prove it.
 */

(function () {
  "use strict";

  const REPO = "maceip/bountynet-genesis";
  const SKIP_NAMES = new Set([".git", "target", "node_modules", ".DS_Store", "out"]);

  // The Value X registered for this repo in registry.json. The widget
  // compares its final computed hash against this to show PASS / FAIL.
  const REGISTERED_VALUE_X =
    "cc28a4bc48236891b90852a24e228b095299b8d08e0813b07b27072683fba7a757143c4092c92eab9797a693e60ee3f6";

  // --------- helpers ---------

  function $(id) {
    return document.getElementById(id);
  }

  function toHex(buf) {
    const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = "";
    for (let i = 0; i < u8.length; i++) {
      s += u8[i].toString(16).padStart(2, "0");
    }
    return s;
  }

  async function sha384(bytes) {
    const digest = await crypto.subtle.digest("SHA-384", bytes);
    return new Uint8Array(digest);
  }

  function shouldSkip(path) {
    const parts = path.split("/");
    for (const seg of parts) {
      if (SKIP_NAMES.has(seg)) return true;
    }
    return false;
  }

  // Byte-lex compare. Paths in this repo are ASCII so UTF-16 vs byte
  // order is equivalent, but we do it the strict way to stay faithful
  // to the Rust impl's String::cmp.
  function cmpBytes(a, b) {
    const ea = new TextEncoder().encode(a);
    const eb = new TextEncoder().encode(b);
    const n = Math.min(ea.length, eb.length);
    for (let i = 0; i < n; i++) {
      if (ea[i] !== eb[i]) return ea[i] - eb[i];
    }
    return ea.length - eb.length;
  }

  function concatBytes(chunks) {
    let total = 0;
    for (const c of chunks) total += c.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
      out.set(c, off);
      off += c.length;
    }
    return out;
  }

  // --------- UI plumbing ---------

  function setStatus(msg, kind) {
    const el = $("vx-status");
    if (!el) return;
    el.textContent = msg;
    el.className = "vx-status " + (kind || "");
  }

  function setProgress(done, total) {
    const bar = $("vx-bar");
    const txt = $("vx-progress-text");
    if (!bar || !txt) return;
    const pct = total > 0 ? Math.round((done / total) * 100) : 0;
    bar.style.width = pct + "%";
    txt.textContent = done + " / " + total + " files  (" + pct + "%)";
  }

  function appendRow(path, hashHex) {
    const log = $("vx-log");
    if (!log) return;
    const row = document.createElement("div");
    row.className = "vx-row";
    const p = document.createElement("span");
    p.className = "vx-path";
    p.textContent = path;
    const h = document.createElement("span");
    h.className = "vx-hash";
    h.textContent = hashHex.slice(0, 24) + "\u2026";
    row.appendChild(p);
    row.appendChild(h);
    log.appendChild(row);
    log.scrollTop = log.scrollHeight;
  }

  function clearLog() {
    const log = $("vx-log");
    if (log) log.innerHTML = "";
    const bar = $("vx-bar");
    if (bar) bar.style.width = "0%";
    const txt = $("vx-progress-text");
    if (txt) txt.textContent = "0 / 0 files";
    const result = $("vx-result");
    if (result) result.innerHTML = "";
  }

  function setResult(ok, computedHex, message) {
    const result = $("vx-result");
    if (!result) return;
    result.innerHTML = "";
    const line1 = document.createElement("div");
    line1.className = "vx-result-hex";
    line1.textContent = "Value X = " + computedHex;
    const line2 = document.createElement("div");
    line2.className = "vx-result-verdict " + (ok ? "vx-ok" : "vx-fail");
    line2.textContent = message;
    result.appendChild(line1);
    result.appendChild(line2);
  }

  // --------- core ---------

  async function fetchTree(ref) {
    const url =
      "https://api.github.com/repos/" +
      REPO +
      "/git/trees/" +
      encodeURIComponent(ref) +
      "?recursive=1";
    const r = await fetch(url, {
      headers: { Accept: "application/vnd.github+json" },
    });
    if (!r.ok) {
      const body = await r.text().catch(() => "");
      throw new Error(
        "github tree api " + r.status + (body ? ": " + body.slice(0, 120) : "")
      );
    }
    const j = await r.json();
    if (j.truncated) {
      throw new Error(
        "github tree response truncated — repo exceeds recursive tree limit. " +
          "use a more specific ref or split the walk."
      );
    }
    return j;
  }

  async function fetchRaw(ref, path) {
    // raw.githubusercontent.com streams the file without counting against
    // the 60/hr anonymous API rate limit.
    const url =
      "https://raw.githubusercontent.com/" +
      REPO +
      "/" +
      encodeURIComponent(ref) +
      "/" +
      path.split("/").map(encodeURIComponent).join("/");
    const r = await fetch(url);
    if (!r.ok) {
      throw new Error("raw fetch " + r.status + " for " + path);
    }
    return new Uint8Array(await r.arrayBuffer());
  }

  async function runWithConcurrency(items, limit, worker, onProgress) {
    const results = new Array(items.length);
    let next = 0;
    let done = 0;
    const workers = [];
    async function pump() {
      while (true) {
        const i = next++;
        if (i >= items.length) return;
        results[i] = await worker(items[i], i);
        done++;
        if (onProgress) onProgress(done, items.length);
      }
    }
    for (let k = 0; k < Math.min(limit, items.length); k++) {
      workers.push(pump());
    }
    await Promise.all(workers);
    return results;
  }

  async function verify(ref) {
    clearLog();
    setStatus("fetching repo tree @ " + ref, "vx-busy");

    const tree = await fetchTree(ref);
    const blobs = tree.tree
      .filter((e) => e.type === "blob")
      .filter((e) => !shouldSkip(e.path));

    blobs.sort((a, b) => cmpBytes(a.path, b.path));
    setStatus(
      "hashing " +
        blobs.length +
        " files client-side (SubtleCrypto SHA-384)",
      "vx-busy"
    );
    setProgress(0, blobs.length);

    // Concurrent fetch + per-file hash. Stream each row into the DOM
    // as it lands so the user can see the walk happening.
    const entries = new Array(blobs.length);
    await runWithConcurrency(
      blobs,
      6,
      async (blob, i) => {
        const bytes = await fetchRaw(ref, blob.path);
        const fh = await sha384(bytes);
        entries[i] = { path: blob.path, hash: fh };
        appendRow(blob.path, toHex(fh));
        return null;
      },
      (done, total) => setProgress(done, total)
    );

    // Final: sha384( for each entry: path || ":" || hex(hash) || "\n" )
    // Entries already sorted by path because blobs was sorted and i preserved.
    const enc = new TextEncoder();
    const chunks = [];
    for (const e of entries) {
      chunks.push(enc.encode(e.path));
      chunks.push(enc.encode(":"));
      chunks.push(enc.encode(toHex(e.hash)));
      chunks.push(enc.encode("\n"));
    }
    const joined = concatBytes(chunks);
    const finalHash = await sha384(joined);
    const computedHex = toHex(finalHash);

    const ok = computedHex === REGISTERED_VALUE_X;
    if (ok) {
      setStatus("done — client-computed Value X matches the registered hash", "vx-ok");
      setResult(
        true,
        computedHex,
        "MATCH  // this ref produces the registered Value X. " +
          "same hash the TDX/SNP/Nitro hardware signed."
      );
    } else {
      setStatus("done — hashes differ", "vx-fail");
      setResult(
        false,
        computedHex,
        "MISMATCH  // expected " +
          REGISTERED_VALUE_X.slice(0, 24) +
          "\u2026  got " +
          computedHex.slice(0, 24) +
          "\u2026  (different ref, or the tree has drifted since registration)"
      );
    }
  }

  // --------- wire up ---------

  function init() {
    const btn = $("vx-run");
    const refInput = $("vx-ref");
    if (!btn || !refInput) return;
    btn.addEventListener("click", async function () {
      btn.disabled = true;
      try {
        const ref = (refInput.value || "main").trim() || "main";
        await verify(ref);
      } catch (e) {
        console.error(e);
        setStatus("error: " + (e && e.message ? e.message : String(e)), "vx-fail");
      } finally {
        btn.disabled = false;
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
