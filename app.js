const RPC_URL = "https://rpc.cookiescan.io";
const EXPLORER_URL = "https://cookiescan.io";
const MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

const KNOWN_TOKENS = {
  "So11111111111111111111111111111111111111112": { name: "Wrapped SOL", symbol: "SOL", legit: true },
  "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": { name: "USD Coin", symbol: "USDC", legit: true },
  "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB": { name: "USDT", symbol: "USDT", legit: true },
};

const SPOOF_TARGETS = ["SOL", "USDC", "USDT", "BONK", "JUP", "RAY", "COOK", "WIF", "PEPE", "TRUMP", "FARTCOIN"];

let wallet = null;
let connection = null;
let scanResults = null;

function $(id) { return document.getElementById(id); }

function truncateAddr(addr) {
  return addr.slice(0, 4) + "..." + addr.slice(-4);
}

function showStatus(el, msg, cls) {
  el.textContent = msg;
  el.className = "scan-status " + (cls || "");
  el.classList.remove("hidden");
}

async function rpcCall(method, params) {
  const res = await fetch(RPC_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params })
  });
  const json = await res.json();
  if (json.error) throw new Error(json.error.message);
  return json.result;
}

async function getBalance(pubkey) {
  const result = await rpcCall("getBalance", [pubkey]);
  return result.value / 1e9;
}

async function getTokenAccounts(pubkey) {
  const result = await rpcCall("getTokenAccountsByOwner", [
    pubkey,
    { programId: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" },
    { encoding: "jsonParsed" }
  ]);
  return result.value || [];
}

async function getToken2022Accounts(pubkey) {
  const result = await rpcCall("getTokenAccountsByOwner", [
    pubkey,
    { programId: "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb" },
    { encoding: "jsonParsed" }
  ]);
  return result.value || [];
}

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
  return dp[m][n];
}

function checkNameSpoofing(name, symbol) {
  if (!name && !symbol) return null;
  const check = (str) => {
    if (!str) return null;
    const upper = str.toUpperCase().replace(/[^A-Z0-9]/g, "");
    for (const target of SPOOF_TARGETS) {
      if (upper === target) continue;
      const dist = levenshtein(upper, target);
      if (dist === 1 && upper.length >= 2) {
        return target;
      }
      const leet = upper.replace(/0/g, "O").replace(/1/g, "I").replace(/3/g, "E").replace(/5/g, "S");
      if (leet === target && upper !== target) {
        return target;
      }
    }
    return null;
  };
  return check(symbol) || check(name);
}

function analyzeToken(tokenAccount, isToken2022) {
  const info = tokenAccount.account.data.parsed.info;
  const mint = info.mint;
  const balance = parseFloat(info.tokenAmount.uiAmountString || "0");
  const decimals = info.tokenAmount.decimals;

  const known = KNOWN_TOKENS[mint];
  const name = known ? known.name : (mint.slice(0, 8) + "...");
  const symbol = known ? known.symbol : "";

  const risks = [];
  let severity = "safe";

  if (isToken2022) {
    risks.push("Token-2022 program (may have transfer fees or freeze authority)");
    severity = "suspicious";
  }

  if (balance > 0 && balance < 0.001 && !known) {
    risks.push("Dust amount: extremely small balance, possible dust attack");
    if (severity !== "suspicious") severity = "review";
  }

  if (!known) {
    risks.push("Unknown token: not in verified token list");
    if (severity === "safe") severity = "review";
  }

  const spoofTarget = checkNameSpoofing(name, symbol);
  if (spoofTarget) {
    risks.push(`Name resembles legitimate token "${spoofTarget}" â possible spoofing`);
    severity = "suspicious";
  }

  return { mint, name, symbol, balance, decimals, isToken2022, risks, severity };
}

function renderResults(results) {
  const { tokens, nativeBal } = results;

  let safe = 0, review = 0, suspicious = 0;
  tokens.forEach(t => {
    if (t.severity === "safe") safe++;
    else if (t.severity === "review") review++;
    else suspicious++;
  });

  $("safeCount").textContent = safe;
  $("reviewCount").textContent = review;
  $("suspiciousCount").textContent = suspicious;
  $("totalCount").textContent = tokens.length;

  $("nativeBalance").innerHTML = `<strong>COOK Balance:</strong> ${nativeBal.toFixed(4)} COOK`;

  renderTokenList(tokens, "all");
  $("results").classList.remove("hidden");
}

function renderTokenList(tokens, filter) {
  const list = $("tokenList");
  list.innerHTML = "";

  const filtered = filter === "all" ? tokens : tokens.filter(t => t.severity === filter);

  if (filtered.length === 0) {
    list.innerHTML = '<div style="text-align:center;color:var(--text-dim);padding:2rem;">No tokens in this category</div>';
    return;
  }

  const sorted = [...filtered].sort((a, b) => {
    const order = { suspicious: 0, review: 1, safe: 2 };
    return order[a.severity] - order[b.severity];
  });

  sorted.forEach(token => {
    const el = document.createElement("div");
    el.className = `token-item risk-${token.severity}`;
    el.dataset.severity = token.severity;

    const badgeClass = `badge-${token.severity}`;
    const risksHtml = token.risks.length
      ? `<div class="token-reason">${token.risks.join(" | ")}</div>`
      : "";

    el.innerHTML = `
      <div>
        <span class="token-badge ${badgeClass}">${token.severity}</span>
      </div>
      <div>
        <div class="token-name">${escapeHtml(token.name)} ${token.symbol ? "(" + escapeHtml(token.symbol) + ")" : ""} ${token.isToken2022 ? '<span style="color:var(--review);font-size:0.7rem">[Token-2022]</span>' : ""}</div>
        <div class="token-mint">${token.mint}</div>
        ${risksHtml}
      </div>
      <div class="token-balance">${token.balance.toLocaleString(undefined, { maximumFractionDigits: 6 })}</div>
    `;
    list.appendChild(el);
  });
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function buildReportMemo(results) {
  const { tokens, nativeBal, walletAddr } = results;
  let safe = 0, review = 0, suspicious = 0;
  tokens.forEach(t => {
    if (t.severity === "safe") safe++;
    else if (t.severity === "review") review++;
    else suspicious++;
  });
  const flagged = tokens.filter(t => t.severity !== "safe").map(t =>
    `${t.mint.slice(0,8)}:${t.severity}`
  ).join(",");

  const memo = `CookieGuard|${walletAddr.slice(0,8)}|${new Date().toISOString().slice(0,10)}|safe:${safe}|review:${review}|suspicious:${suspicious}|flagged:[${flagged}]`;
  return memo.slice(0, 566);
}

async function sendMemoTx(memo) {
  const provider = wallet;
  const pubkey = provider.publicKey;
  const pubkeyBytes = pubkey.toBytes();

  const recentBlockhash = await rpcCall("getLatestBlockhash", [{ commitment: "finalized" }]);
  const blockhash = recentBlockhash.value.blockhash;

  const memoData = new TextEncoder().encode(memo);
  const memoProgramKey = new Uint8Array(32);
  const decoded = decodeBase58(MEMO_PROGRAM_ID);
  memoProgramKey.set(decoded);

  const instruction = {
    keys: [{ pubkey: pubkey, isSigner: true, isWritable: true }],
    programId: memoProgramKey,
    data: memoData
  };

  const tx = await createAndSignTx(provider, blockhash, [instruction]);
  const sig = await rpcCall("sendTransaction", [tx, { encoding: "base64" }]);
  return sig;
}

function decodeBase58(str) {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const result = [];
  for (const char of str) {
    let carry = ALPHABET.indexOf(char);
    if (carry < 0) throw new Error("Invalid base58 char: " + char);
    for (let i = 0; i < result.length; i++) {
      carry += result[i] * 58;
      result[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      result.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (const char of str) {
    if (char === "1") result.push(0);
    else break;
  }
  return new Uint8Array(result.reverse());
}

async function createAndSignTx(provider, blockhash, instructions) {
  if (provider.signTransaction) {
    const { Transaction, PublicKey: PK, TransactionInstruction } = window.solanaWeb3 || {};
    if (Transaction) {
      const tx = new Transaction();
      tx.recentBlockhash = blockhash;
      tx.feePayer = provider.publicKey;
      instructions.forEach(ix => {
        tx.add(new TransactionInstruction({
          keys: ix.keys.map(k => ({ pubkey: k.pubkey, isSigner: k.isSigner, isWritable: k.isWritable })),
          programId: new PK(ix.programId),
          data: window.Buffer ? window.Buffer.from(ix.data) : ix.data
        }));
      });
      const signed = await provider.signTransaction(tx);
      const serialized = signed.serialize();
      return btoa(String.fromCharCode(...serialized));
    }
  }

  if (provider.signAndSendTransaction) {
    const { Transaction, PublicKey: PK, TransactionInstruction } = window.solanaWeb3 || {};
    if (Transaction) {
      const tx = new Transaction();
      tx.recentBlockhash = blockhash;
      tx.feePayer = provider.publicKey;
      instructions.forEach(ix => {
        tx.add(new TransactionInstruction({
          keys: ix.keys.map(k => ({ pubkey: k.pubkey, isSigner: k.isSigner, isWritable: k.isWritable })),
          programId: new PK(ix.programId),
          data: window.Buffer ? window.Buffer.from(ix.data) : ix.data
        }));
      });
      const { signature } = await provider.signAndSendTransaction(tx);
      return signature;
    }
  }

  throw new Error("Wallet does not support transaction signing");
}

async function connectWallet() {
  const nightly = window.nightly?.solana || window.solana;
  if (!nightly) {
    alert("Please install Nightly wallet extension from nightly.app");
    return;
  }

  try {
    const resp = await nightly.connect();
    wallet = nightly;
    const addr = wallet.publicKey.toString();
    $("walletAddr").textContent = truncateAddr(addr);
    $("connectBtn").classList.add("hidden");
    $("walletInfo").classList.remove("hidden");
    $("landing").classList.add("hidden");
    $("scanner").classList.remove("hidden");
  } catch (e) {
    console.error("Connect failed:", e);
    alert("Failed to connect wallet: " + e.message);
  }
}

function disconnectWallet() {
  if (wallet && wallet.disconnect) wallet.disconnect();
  wallet = null;
  scanResults = null;
  $("connectBtn").classList.remove("hidden");
  $("walletInfo").classList.add("hidden");
  $("scanner").classList.add("hidden");
  $("landing").classList.remove("hidden");
  $("results").classList.add("hidden");
}

async function scanWallet() {
  if (!wallet) return;
  const addr = wallet.publicKey.toString();
  const statusEl = $("scanStatus");
  const scanBtn = $("scanBtn");

  scanBtn.disabled = true;
  scanBtn.textContent = "Scanning...";
  scanBtn.classList.add("scanning");
  showStatus(statusEl, "Connecting to Cookie Chain RPC...");

  try {
    showStatus(statusEl, "Reading COOK balance...");
    const nativeBal = await getBalance(addr);

    showStatus(statusEl, "Reading SPL token accounts...");
    const splAccounts = await getTokenAccounts(addr);

    showStatus(statusEl, "Reading Token-2022 accounts...");
    const t22Accounts = await getToken2022Accounts(addr);

    showStatus(statusEl, `Analyzing ${splAccounts.length + t22Accounts.length} tokens...`);

    const tokens = [];
    splAccounts.forEach(acc => tokens.push(analyzeToken(acc, false)));
    t22Accounts.forEach(acc => tokens.push(analyzeToken(acc, true)));

    scanResults = { tokens, nativeBal, walletAddr: addr };
    renderResults(scanResults);

    const suspicious = tokens.filter(t => t.severity === "suspicious").length;
    const review = tokens.filter(t => t.severity === "review").length;

    if (suspicious > 0) {
      showStatus(statusEl, `Scan complete. ${suspicious} suspicious token(s) found!`, "error");
    } else if (review > 0) {
      showStatus(statusEl, `Scan complete. ${review} token(s) need review.`);
    } else {
      showStatus(statusEl, "Scan complete. Your wallet looks clean!");
    }
  } catch (e) {
    console.error("Scan failed:", e);
    showStatus(statusEl, "Scan failed: " + e.message, "error");
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = "Scan My Wallet";
    scanBtn.classList.remove("scanning");
  }
}

async function saveReport() {
  if (!scanResults || !wallet) return;
  const reportBtn = $("reportBtn");
  const reportStatus = $("reportStatus");
  const txLink = $("txLink");

  reportBtn.disabled = true;
  reportBtn.textContent = "Sending...";
  showStatus(reportStatus, "Building memo transaction...");

  try {
    const memo = buildReportMemo(scanResults);
    showStatus(reportStatus, "Please approve the transaction in your wallet...");

    const sig = await sendMemoTx(memo);

    reportStatus.textContent = "Report saved on-chain!";
    reportStatus.className = "report-status success";
    reportStatus.classList.remove("hidden");

    txLink.innerHTML = `<a href="${EXPLORER_URL}/tx/${sig}" target="_blank">View transaction on CookieScan &rarr;</a>`;
    txLink.classList.remove("hidden");
  } catch (e) {
    console.error("Report failed:", e);
    reportStatus.textContent = "Failed: " + e.message;
    reportStatus.className = "report-status error";
    reportStatus.classList.remove("hidden");
  } finally {
    reportBtn.disabled = false;
    reportBtn.textContent = "Save Report On-Chain";
  }
}

$("connectBtn").addEventListener("click", connectWallet);
$("disconnectBtn").addEventListener("click", disconnectWallet);
$("scanBtn").addEventListener("click", scanWallet);
$("reportBtn").addEventListener("click", saveReport);

document.querySelectorAll(".filter-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    if (scanResults) renderTokenList(scanResults.tokens, btn.dataset.filter);
  });
});

if (window.nightly?.solana?.isConnected || window.solana?.isConnected) {
  connectWallet();
}

