CenDeFi – Multi-Chain Crypto Wallet Bot (Telegram)
Secure | Multi-Chain | TON + EVM | AI-Integrated

CenDeFi is a crypto-only multi-chain wallet system built into a Telegram bot — allowing users to send, receive, scan, bridge, and eventually swap assets across EVM and TON blockchains.
It uses on-chain transactions, non-custodial encrypted wallets, PIN-locking, and AI-powered assistance for a smooth, secure, and accessible experience.

🔥 Current Status (In Development)

The bot is fully operational with:

✔ Multi-Chain Wallet Generation

Polygon (MATIC)

BSC (BNB)

Base (ETH)

Ethereum (ETH)

TON (TON native + Jettons)

Each user receives unique non-custodial wallets generated on-chain.

✔ Secure Private Key Storage

AES-256 encrypted private keys

Stored only after encryption

No plaintext key exposure

✔ PIN Security Layer (4–6 digits)

Required before sensitive actions:

Viewing balances

Sending crypto

Refreshing balances

5 failed attempts → 5-minute lockout

Built-in warning for users not to share PIN

✔ Send & Receive Crypto

Fully working send flow with:

Native assets (TON, MATIC, BNB, ETH)

Tokens (USDT, USDC, ERC20)

TON Jettons (USDT, USDC)

Cross-user username→address resolution

Gas estimation for EVM

TON fee estimation placeholder

Transaction confirmation summary

Automatic notification to the recipient:
“You received X from @username”

✔ Token Scanner

Auto-detects common tokens & Jettons:

ERC20s on EVM

Jettons on TON (via TonAPI & TonCenter fallback)

✔ TON Full Integration

Native TON send

Jetton send (USDT/USDC)

Jetton wallet mapping

Toncenter RPC + TonAPI integration

Explorer links using tonscan.org

🔗 Supported Chains
| Chain    | Native Token | Tokens/JETTONS           | Status |
| -------- | ------------ | ------------------------ | ------ |
| Polygon  | MATIC        | USDT, USDC               | ✓      |
| BSC      | BNB          | USDT, USDC               | ✓      |
| Base     | ETH          | USDC                     | ✓      |
| Ethereum | ETH          | USDT, USDC               | ✓      |
| TON      | TON          | USDT Jetton, USDC Jetton | ✓      |

🚀 Features (Current Build)
1. Multi-Chain Non-Custodial Wallet

Each user automatically receives:

4 EVM wallets

1 TON wallet
Generated and encrypted locally.

2. Secure Send Flow

Username or address-based sending

Native + token transfers

TON Jetton transfers

Gas estimation

Full transaction confirmation step

Automatic rollback on failure

Automatic PIN protection

3. Receive Flow

QR code generation

Copy-address buttons

Multi-chain address display

4. Transaction History

Stored in MongoDB and viewable via /history.

5. Token Scanning

EVM ERC20 scanning

TON Jetton scanning

Results formatted neatly

6. AI Assistant (Cen AI)

For education, troubleshooting, and general crypto questions.

🛡️ Security Model
✔ AES-256-CTR encryption for private keys

Stored in Mongo as encrypted hex strings.

✔ PIN-protected actions

All sensitive actions require PIN verification.

✔ Auto lockout after 5 attempts

Protects users in case someone accesses their Telegram account.

✔ Fully non-custodial

All transactions are executed client-side through user’s private keys.

✔ No local currency / fiat processing

Removed for simplicity and regulatory compliance.

✔ No bots or admins can see user funds

Keys remain encrypted at all times.

📐 High-Level Architecture
User → Telegram Bot → Node.js Backend → MongoDB
                                ↳ EVM RPC Providers
                                ↳ TON RPC / TonAPI
Core Components

bot.js: Main logic (wallet, send, PIN, AI, TON integration)

MongoDB: Store encrypted keys, PIN hashes, tx history

TONWeb: Native TON + Jetton interaction

Ethers.js: EVM transactions

Axios: RPC + API calls

🛠️ Installation & Setup
git clone <repo_url>
cd cen-defi-wallet-bot

npm install

Start the bot
node bot.js

🔧 Environment Variables (.env)

Below is the recommended .env layout:
TELEGRAM_BOT_TOKEN=your_bot_token

MONGO_URI=mongodb+srv://…

ENCRYPTION_SECRET=long_random_secret_key

POLYGON_RPC=https://…
BSC_RPC=https://…
BASE_RPC=https://…
ETH_RPC=https://…

TON_RPC=https://toncenter.com/api/v2/jsonRPC
TON_API_KEY=optional

OPENAI_API_KEY=your_key_here

PORT=3000
CONFIRMATIONS=1

🧭 Roadmap (Next Steps)
Phase 1 — Completed

✔ Multi-chain wallet generation
✔ TON + Jetton integration
✔ Secure PIN system
✔ Encrypted keys
✔ Gas estimation
✔ Token scanning
✔ AI integration
✔ History system

Phase 2 — In Progress

🚧 Swap Engine

EVM swaps via 1inch

TON swaps via Ston.fi

Smooth token selection menus

🚧 Cross-chain Bridge

Wormhole bridge integration

Automatic chain detection

Phase 3 — Future

✨ Full Web Dashboard
✨ NFC Card (CenCard) integration
✨ iOS + Android light clients
✨ Staking & savings vaults
✨ CenDeFi token
✨ Multi-sig accounts

🤝 Contribution

Pull requests are welcome.
For major changes, open an issue to discuss what you would like to modify.

📜 License

MIT License — free to use, modify, and build upon.
✔ Cen AI Integration

Users can type questions directly to an embedded AI assistant (OpenAI API).
