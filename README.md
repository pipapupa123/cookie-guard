# Cookie Guard â Wallet Security Scanner for Cookie Chain

A web application that scans your Cookie Chain wallet for security threats: dust attacks, transfer-fee token traps (Token-2022), name spoofing, and suspicious airdrops. Get a risk assessment for every token, then record your audit on-chain.

## The Problem

SVM chains inherit Solana's scam token ecosystem. Users receive unsolicited tokens designed to:
- **Dust attacks**: Tiny worthless amounts that track wallet activity or lure users to phishing dApps
- **Transfer-fee traps**: Token-2022 tokens with hidden transfer fees that drain value on every trade
- **Name spoofing**: Tokens impersonating legitimate projects (e.g., "S0L" instead of "SOL")
- **Airdrop spam**: Mass-distributed tokens preceding pump-and-dumps or phishing campaigns

Cookie Chain users currently have no dedicated tool to identify these threats.

## What Cookie Guard Does

1. **Connect** your wallet via Nightly
2. **Scan** all token holdings (SPL + Token-2022) via Cookie Chain RPC
3. **Analyze** each token against known risk indicators
4. **Report** â save your scan results as a memo transaction on Cookie Chain

### Risk Indicators

| Indicator | Severity | Description |
|-----------|----------|-------------|
| Token-2022 | Suspicious | May have transfer fees or freeze authority |
| Dust amount | Review | Extremely small balance from unknown source |
| Unknown token | Review | Not in verified token list |
| Name spoofing | Suspicious | Name resembles a legitimate token |

## Tech Stack

- Vanilla HTML/CSS/JavaScript (no build step)
- Cookie Chain RPC (`rpc.cookiescan.io`)
- Nightly wallet adapter
- On-chain memo transactions via Memo Program

## Setup

No build required. Open `index.html` in a browser, or deploy to any static hosting.

```bash
# Local development
python3 -m http.server 8080
# Then open http://localhost:8080

# Or deploy to Vercel
npx vercel --prod
```

## Project Structure

```
cookie-guard/
  index.html    â Main page
  style.css     â Styling (dark theme, responsive)
  app.js        â Wallet connection, token scanning, risk analysis, memo tx
  README.md     â This file
```

## How It Works

1. Connects to Cookie Chain RPC at `rpc.cookiescan.io`
2. Reads all SPL and Token-2022 token accounts for the connected wallet
3. Runs each token through risk analysis:
   - Checks against known legitimate token list
   - Detects Token-2022 program usage (transfer-fee risk)
   - Measures dust-level balances
   - Runs Levenshtein distance check for name spoofing against known tokens
4. Displays results in a filterable dashboard with severity badges
5. Optionally writes a scan summary as a memo transaction on-chain

## License

MIT
# cookie-guard
Wallet Security Scanner for Cookie Chain — detect dust attacks, transfer-fee traps, name spoofing, and airdrop spam
