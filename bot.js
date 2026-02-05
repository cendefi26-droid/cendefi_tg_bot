/**
 * CenDeFi bot.js — FULL with TON + Jetton support (USDT / USDC)
 * - EVM: polygon, bsc, base, ethereum (ethers.js)
 * - TON: wallet generation, native send, jetton scan, jetton send (tonweb)
 * - Explorer for TON: tonscan.org (as requested)
 *
 * REQUIRED env vars (minimum):
 * TELEGRAM_BOT_TOKEN, MONGO_URI, ENCRYPTION_SECRET,
 * POLYGON_RPC, BSC_RPC, BASE_RPC, ETH_RPC, TON_RPC
 *
 * Install:
 * npm i tonweb axios node-telegram-bot-api express body-parser mongoose ethers node-fetch
 */

require("dotenv").config();
const TelegramBot = require("node-telegram-bot-api");
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const crypto = require("crypto");
const axios = require("axios");
const fetch = require("node-fetch");
const { ethers } = require("ethers");

// TON library
let TonWeb = null;
try {
  TonWeb = require("tonweb");
} catch (e) {
  console.warn("tonweb not installed. Run `npm i tonweb` to enable TON features.");
}

// ---------- Config ----------
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
if (!BOT_TOKEN) {
  console.error("Missing TELEGRAM_BOT_TOKEN in .env");
  process.exit(1);
}
const ENCRYPTION_SECRET = process.env.ENCRYPTION_SECRET || "change_this_secret";
const CONFIRMATIONS = parseInt(process.env.CONFIRMATIONS || "1", 10);
const WEBHOOK_PORT = parseInt(process.env.PORT || "3000", 10);
const TON_NATIVE_FEE_NANO = BigInt(10000000); // 0.01 TON
const TON_JETTON_FORWARD_NANO = BigInt(20000000); // 0.02 TON
const TON_JETTON_GAS_BUFFER_NANO = BigInt(5000000); // 0.005 TON

// Chain config (tonscan explorer set for TON)
const CHAIN_CONFIG = {
  polygon:  { id: "polygon",  name: "Polygon",  symbol: "MATIC", rpc: process.env.POLYGON_RPC || "https://polygon-rpc.com", explorer: "https://polygonscan.com/tx/" },
  bsc:      { id: "bsc",      name: "BSC",      symbol: "BNB",  rpc: process.env.BSC_RPC || "https://bsc-dataseed.binance.org/", explorer: "https://bscscan.com/tx/" },
  base:     { id: "base",     name: "Base",     symbol: "ETH",  rpc: process.env.BASE_RPC || "https://base-mainnet.publicnode.com", explorer: "https://basescan.org/tx/" },
  ethereum: { id: "ethereum", name: "Ethereum", symbol: "ETH",  rpc: process.env.ETH_RPC || "https://cloudflare-eth.com", explorer: "https://etherscan.io/tx/" },
  ton:      { id: "ton",      name: "TON",      symbol: "TON",  rpc: process.env.TON_RPC || null, explorer: "https://tonscan.org/tx/" },
};
const SUPPORTED_CHAINS = Object.keys(CHAIN_CONFIG);

// ---------- Init bot + express ----------
const bot = new TelegramBot(BOT_TOKEN, { polling: true });
const app = express();
app.use(bodyParser.json());

// ---------- Providers for EVM ----------
const providers = {};
for (const k of SUPPORTED_CHAINS) {
  if (k === "ton") { providers[k] = null; continue; }
  try {
    providers[k] = new ethers.JsonRpcProvider(CHAIN_CONFIG[k].rpc);
    console.log(`Provider configured for ${k}`);
  } catch (e) {
    console.warn(`Provider failed for ${k}:`, e?.message || e);
    providers[k] = null;
  }
}

// ---------- TON helper object (if tonweb installed) ----------
let tonwebProvider = null;
if (TonWeb && CHAIN_CONFIG.ton.rpc) {
  try {
    tonwebProvider = new TonWeb.HttpProvider(CHAIN_CONFIG.ton.rpc, { apiKey: process.env.TON_API_KEY || "" });
    console.log("TonWeb provider configured.");
  } catch (e) {
    console.warn("TonWeb provider init error:", e?.message || e);
    tonwebProvider = null;
  }
}

// ---------- Encryption helpers ----------
function aesKeyFromSecret(secret) {
  return crypto.createHash("sha256").update(secret).digest();
}
function encryptPrivateKey(plain) {
  const key = aesKeyFromSecret(ENCRYPTION_SECRET);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-ctr", key, iv);
  const enc = Buffer.concat([cipher.update(Buffer.from(plain, "utf8")), cipher.final()]);
  return iv.toString("hex") + ":" + enc.toString("hex");
}
function decryptPrivateKey(enc) {
  const [ivHex, dataHex] = enc.split(":");
  if (!ivHex || !dataHex) throw new Error("Invalid encrypted data");
  const iv = Buffer.from(ivHex, "hex");
  const data = Buffer.from(dataHex, "hex");
  const key = aesKeyFromSecret(ENCRYPTION_SECRET);
  const decipher = crypto.createDecipheriv("aes-256-ctr", key, iv);
  const dec = Buffer.concat([decipher.update(data), decipher.final()]);
  return dec.toString("utf8");
}

// ---------- MongoDB ----------
if (!process.env.MONGO_URI) {
  console.error("Missing MONGO_URI in .env");
  process.exit(1);
}
mongoose.connect(process.env.MONGO_URI, { dbName: "cendefi" })
  .then(() => console.log("Connected to MongoDB"))
  .catch(err => { console.error("MongoDB error:", err); process.exit(1); });

// ---------- Schemas ----------
const walletSubSchema = new mongoose.Schema({
  address: String,
  privateKeyEnc: String, // for EVM: secp256k1 privkey; for TON: ed25519 secret hex encoded
}, { _id: false });

const userSchema = new mongoose.Schema({
  telegramId: { type: String, index: true, unique: true },
  whatsappNumber: { type: String, index: true, unique: true, sparse: true },
  username: String,
  firstName: String,
  createdAt: { type: Date, default: Date.now },
  wallets: { type: Map, of: walletSubSchema, default: {} },
  preferredChain: { type: String, default: "polygon" },
  state: String,
  tempData: mongoose.Schema.Types.Mixed,
  pinHash: { type: String, default: null },
  pinAttempts: { type: Number, default: 0 },
  pinLockedUntil: { type: Date, default: null },
});
const User = mongoose.model("User", userSchema);

const txSchema = new mongoose.Schema({
  userId: String,
  from: String,
  to: String,
  amount: String,
  token: { type: String, default: "NATIVE" },
  txHash: String,
  chain: String,
  status: String,
  createdAt: { type: Date, default: Date.now },
});
const Tx = mongoose.model("Tx", txSchema);

// ---------- In-memory flow stores ----------
const sendState = {};     // telegram send flows
const pinSessions = {};   // telegram pin entry flows
const pinSetSessions = {}; // telegram setpin flows
const sendStateWA = {};   // whatsapp send flows
const pinSessionsWA = {}; // whatsapp pin entry flows
const pinSetSessionsWA = {}; // whatsapp setpin flows

// ---------- Helpers ----------
function shortAddr(addr) { if (!addr) return "—"; return `${addr.slice(0,6)}...${addr.slice(-4)}`; }
function explorerLink(chain, txHash) { if (!txHash) return ""; return `${CHAIN_CONFIG[chain].explorer}${txHash}`; }
function sendSafeError(chatId) { return bot.sendMessage(chatId, "⚠️ Something went wrong — try again later."); }
function isValidChain(chain) { return SUPPORTED_CHAINS.includes(chain); }
function isValidTonAddress(addr) {
  if (!TonWeb || !TonWeb.utils || !TonWeb.utils.Address) return false;
  try { new TonWeb.utils.Address(addr); return true; } catch (_) { return false; }
}

// ---------- PIN helpers ----------
function hashPIN(pin) { return crypto.createHash("sha256").update(pin).digest("hex"); }
async function requestPINForAction(telegramId, chatId, action, params = {}) {
  const user = await User.findOne({ telegramId });
  if (!user) return bot.sendMessage(chatId, "User record missing.");
  if (user.pinLockedUntil && new Date(user.pinLockedUntil) > new Date()) {
    const mins = Math.ceil((new Date(user.pinLockedUntil) - Date.now())/60000);
    return bot.sendMessage(chatId, `🔒 Too many wrong attempts. Try again in ${mins} minute(s).`);
  }
  if (!user.pinHash) {
    return bot.sendMessage(chatId, "🔐 You must set a PIN first. Use /setpin");
  }
  const sent = await bot.sendMessage(chatId, "🔐 Enter your 4–6 digit PIN:", { reply_markup: { force_reply: true, selective: true }});
  pinSessions[telegramId] = { action, params, botPromptMessageId: sent.message_id };
  return;
}
function clearPinSession(telegramId) { if (pinSessions[telegramId]) delete pinSessions[telegramId]; }

async function requestPINForActionWhatsApp(whatsappNumber, action, params = {}) {
  const user = await User.findOne({ whatsappNumber });
  if (!user) return sendWhatsAppText(whatsappNumber, "User record missing.");
  if (user.pinLockedUntil && new Date(user.pinLockedUntil) > new Date()) {
    const mins = Math.ceil((new Date(user.pinLockedUntil) - Date.now())/60000);
    return sendWhatsAppText(whatsappNumber, `🔒 Too many wrong attempts. Try again in ${mins} minute(s).`);
  }
  if (!user.pinHash) {
    return sendWhatsAppText(whatsappNumber, "🔐 You must set a PIN first. Send `setpin`.");
  }
  await sendWhatsAppText(whatsappNumber, "🔐 Enter your 4–6 digit PIN:");
  pinSessionsWA[whatsappNumber] = { action, params };
}

// ---------- Wallet helpers ----------
async function getOrCreateUser(from) {
  const telegramId = String(from.id);
  let user = await User.findOne({ telegramId });
  if (!user) {
    user = await User.create({ telegramId, username: from.username || "", firstName: from.first_name || "" });
    console.log("Created user", telegramId);
  } else {
    if (from.username && user.username !== from.username) { user.username = from.username; await user.save(); }
  }
  return user;
}

async function getOrCreateWhatsAppUser(whatsappNumber) {
  let user = await User.findOne({ whatsappNumber });
  if (!user) {
    user = await User.create({ whatsappNumber, username: "", firstName: "" });
    console.log("Created WhatsApp user", whatsappNumber);
  }
  return user;
}

// Ensure / create wallet for chain. TON uses ed25519 private key stored as hex in privateKeyEnc
async function ensureChainWallet(user, chain) {
  if (!isValidChain(chain)) throw new Error("Unsupported chain");
  const entry = user.wallets.get(chain);
  if (entry && entry.address && entry.privateKeyEnc) return entry;

  if (chain === "ton") {
    if (!TonWeb) throw new Error("TON support requires tonweb. Install with `npm i tonweb`");
    if (!CHAIN_CONFIG.ton.rpc) throw new Error("TON_RPC not configured in .env");
    // generate ed25519 keypair
    const nacl = TonWeb.utils.nacl;
    const keyPair = nacl.sign.keyPair();
    const secretHex = Buffer.from(keyPair.secretKey).toString("hex");
    // tonweb provider & wallet class
    const tonweb = new TonWeb(tonwebProvider || new TonWeb.HttpProvider(CHAIN_CONFIG.ton.rpc));
    // Try wallet v3R2 or fallback to v3
    const WalletClass = (TonWeb.wallet && (TonWeb.wallet.all && (TonWeb.wallet.all.v3R2 || TonWeb.wallet.all.v3))) || TonWeb.wallet;
    if (!WalletClass) throw new Error("TonWeb wallet class not found");
    const wallet = new WalletClass(tonweb.provider, { publicKey: keyPair.publicKey });
    const addressObj = await wallet.getAddress();
    const address = addressObj.toString(true, true, true);
    const enc = encryptPrivateKey(secretHex);
    const data = { address, privateKeyEnc: enc };
    user.wallets.set("ton", data);
    await user.save();
    console.log("Created TON wallet for user", user.telegramId, address);
    return data;
  } else {
    const wallet = ethers.Wallet.createRandom();
    const enc = encryptPrivateKey(wallet.privateKey);
    const data = { address: wallet.address, privateKeyEnc: enc };
    user.wallets.set(chain, data);
    await user.save();
    return data;
  }
}

// ---------- getChainBalance (EVM + TON) ----------
async function getChainBalance(user, chain) {
  if (!isValidChain(chain)) throw new Error("Unsupported chain");
  if (chain === "ton") {
    if (!CHAIN_CONFIG.ton.rpc) throw new Error("TON RPC not configured");
    const entry = user.wallets.get("ton");
    if (!entry || !entry.address) return "0";
    try {
      // prefer TonAPI if available (free path), then toncenter RPC
      // Attempt TonAPI first:
      try {
        const tonapiKey = process.env.TONAPI_KEY || "";
        const res = await axios.get(`https://tonapi.io/v2/accounts/${entry.address}`, { headers: tonapiKey ? { "x-api-key": tonapiKey } : {} });
        if (res.data && typeof res.data.balance !== "undefined") {
          const nano = BigInt(res.data.balance || "0");
          const ton = Number(nano) / 1e9;
          return String(ton);
        }
      } catch (e) {
        // fallback to toncenter/ton RPC JSON-RPC getAccount
      }
      // Toncenter / generic RPC JSON-RPC
      const payload = { jsonrpc: "2.0", id: 1, method: "getAccount", params: { account: entry.address } };
      const res = await axios.post(CHAIN_CONFIG.ton.rpc, payload, { headers: { "Content-Type": "application/json" } });
      if (res.data && res.data.result && typeof res.data.result.balance !== "undefined") {
        const nano = BigInt(res.data.result.balance || "0");
        const ton = Number(nano) / 1e9;
        return String(ton);
      }
    } catch (e) {
      console.debug("TON balance fetch error:", e?.message || e);
      return "n/a";
    }
    return "n/a";
  } else {
    const provider = providers[chain];
    if (!provider) throw new Error("Provider not configured for " + chain);
    const entry = user.wallets.get(chain);
    if (!entry || !entry.address) return "0";
    const bal = await provider.getBalance(entry.address);
    return ethers.formatEther(bal);
  }
}

// ---------- Token list (include USDT + USDC across chains + TON jettons) ----------
const TOKEN_LIST = {
  polygon: [
    { symbol: "MATIC", address: null },
    { symbol: "USDC",  address: "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174" },
    { symbol: "USDT",  address: "0x3813e82e6f7098b9583fc0f33a96202018b6803" },
  ],
  bsc: [
    { symbol: "BNB", address: null },
    { symbol: "USDT", address: "0x55d398326f99059fF775485246999027B3197955" },
    { symbol: "USDC", address: "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d" },
  ],
  ethereum: [
    { symbol: "ETH", address: null },
    { symbol: "USDT", address: "0xdAC17F958D2ee523a2206206994597C13D831ec7" },
    { symbol: "USDC", address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eb48" },
  ],
  base: [
    { symbol: "ETH", address: null },
    { symbol: "USDC", address: "0x1a13f4ca1d028320a707d99520abfefca3998b7f" },
  ],
  ton: [
    { symbol: "TON", address: null },
    // Verified Jetton addresses (as provided earlier). Update if you find alternate addresses.
    { symbol: "USDT", address: "EQC2H5S2TvQBfwb8jKVvGs0p9Ev2nT9c2hv0LXxvGUNmEoL6" },
    { symbol: "USDC", address: "EQBwcPz2pY3drR5uNtTBQFEfz1JXNtnX0F9FbMJ66yRdEIBj" },
  ]
};

// ---------- ERC20 ABI minimal ----------
const ERC20_ABI = [
  "function balanceOf(address owner) view returns (uint256)",
  "function decimals() view returns (uint8)",
  "function symbol() view returns (string)",
  "function transfer(address to, uint amount) returns (bool)"
];

// ---------- Token scanning (EVM + TON) ----------
async function scanTokensForAddress(chain, address) {
  if (!isValidChain(chain)) throw new Error("Unsupported chain");
  if (chain === "ton") return await scanTONTokens(address);
  const provider = providers[chain];
  if (!provider) throw new Error("Provider missing for " + chain);
  const tokens = TOKEN_LIST[chain] || [];
  const out = [];
  for (const t of tokens) {
    try {
      if (!t.address) {
        const bal = await provider.getBalance(address);
        const val = Number(ethers.formatEther(bal));
        if (val > 0) out.push({ symbol: t.symbol, balance: val, address: null });
      } else {
        const contract = new ethers.Contract(t.address, ERC20_ABI, provider);
        const raw = await contract.balanceOf(address);
        if (!raw) continue;
        if (raw === 0n) continue;
        let decimals = 18;
        try { decimals = await contract.decimals(); } catch (_) {}
        const symbol = t.symbol || (await contract.symbol().catch(() => "TOK"));
        const value = Number(ethers.formatUnits(raw, decimals));
        if (value > 0) out.push({ symbol, balance: value, address: t.address });
      }
    } catch (e) {
      console.debug("Token scan error", chain, t.address, e?.message || e);
    }
  }
  return out;
}

// ---------- TON scanning helpers ----------
async function scanTONTokens(address) {
  const out = [];
  // Try TonAPI first (friendly), then fall back to toncenter RPC.
  try {
    const tonapiKey = process.env.TONAPI_KEY || "";
    const headers = tonapiKey ? { "x-api-key": tonapiKey } : {};
    const res = await axios.get(`https://tonapi.io/v2/accounts/${address}/jettons`, { headers });
    if (res.data && res.data.balances) {
      for (const b of res.data.balances) {
        const symbol = (b.jetton && (b.jetton.symbol || b.jetton.metadata && b.jetton.metadata.symbol)) || (b.jetton && b.jetton.title) || "JETTON";
        const decimals = (b.jetton && (b.jetton.metadata && b.jetton.metadata.decimals)) || 9;
        const bal = Number(b.balance) / (10 ** decimals);
        if (bal > 0) out.push({ symbol, balance: bal, address: b.jetton.address });
      }
      // also add native TON if returned by API (tonapi returns native balance separately)
      try {
        const acct = await axios.get(`https://tonapi.io/v2/accounts/${address}`, { headers });
        if (acct.data && typeof acct.data.balance !== "undefined") {
          const tonBal = Number(BigInt(acct.data.balance || "0")) / 1e9;
          if (tonBal > 0) out.unshift({ symbol: "TON", balance: tonBal, address: null });
        }
      } catch (_) {}
      return out;
    }
  } catch (e) {
    console.debug("TonAPI jetton fetch failed:", e?.message || e);
  }

  // Toncenter RPC fallback: get native balance only (jetton scanning through RPC is complicated)
  try {
    if (!CHAIN_CONFIG.ton.rpc) return out;
    const payload = { jsonrpc: "2.0", id: 1, method: "getAccount", params: { account: address } };
    const res = await axios.post(CHAIN_CONFIG.ton.rpc, payload, { headers: { "Content-Type": "application/json" } });
    if (res.data && res.data.result && typeof res.data.result.balance !== "undefined") {
      const nano = BigInt(res.data.result.balance || "0");
      const ton = Number(nano) / 1e9;
      if (ton > 0) out.push({ symbol: "TON", balance: ton, address: null });
    }
  } catch (e) {
    console.debug("TON RPC fallback failed:", e?.message || e);
  }
  return out;
}

async function getTonNanoBalance(address) {
  if (!CHAIN_CONFIG.ton.rpc) throw new Error("TON RPC not configured");
  try {
    const tonapiKey = process.env.TONAPI_KEY || "";
    const res = await axios.get(`https://tonapi.io/v2/accounts/${address}`, { headers: tonapiKey ? { "x-api-key": tonapiKey } : {} });
    if (res.data && typeof res.data.balance !== "undefined") {
      return BigInt(res.data.balance || "0");
    }
  } catch (_) {}
  const payload = { jsonrpc: "2.0", id: 1, method: "getAccount", params: { account: address } };
  const res = await axios.post(CHAIN_CONFIG.ton.rpc, payload, { headers: { "Content-Type": "application/json" } });
  if (res.data && res.data.result && typeof res.data.result.balance !== "undefined") {
    return BigInt(res.data.result.balance || "0");
  }
  return null;
}

async function getJettonDecimals(jettonMaster) {
  let decimals = 9;
  try {
    const tonapiKey = process.env.TONAPI_KEY || "";
    const metaRes = await axios.get(`https://tonapi.io/v2/jettons/${jettonMaster}`, { headers: tonapiKey ? { "x-api-key": tonapiKey } : {} });
    if (metaRes.data && metaRes.data.metadata && typeof metaRes.data.metadata.decimals !== "undefined") {
      decimals = Number(metaRes.data.metadata.decimals);
    }
  } catch (_) {}
  return decimals;
}

// ---------- Gas estimation (EVM) and simple TON placeholder fee ----------
async function estimateGasForTransfer(chain, fromAddress, toAddress, amount, tokenAddress = null) {
  if (!isValidChain(chain)) throw new Error("Unsupported chain");
  if (chain === "ton") {
    // TON gas differs; return a small placeholder estimate (TON fee in TON)
    // We will estimate around 0.001 TON for simple transfer, actual fee depends on network.
    return { gasLimit: "n/a", gasPriceGwei: "n/a", estimatedFeeNative: 0.001, nativeSymbol: "TON" };
  }
  const provider = providers[chain];
  if (!provider) throw new Error("Provider missing");
  const amtStr = String(amount);
  if (!tokenAddress) {
    const tx = { from: fromAddress, to: toAddress, value: ethers.parseEther(amtStr) };
    const gasLimit = await provider.estimateGas(tx);
    const gasPrice = await provider.getGasPrice();
    const fee = Number(ethers.formatEther(gasLimit * gasPrice));
    return { gasLimit: gasLimit.toString(), gasPriceGwei: ethers.formatUnits(gasPrice, "gwei"), estimatedFeeNative: fee, nativeSymbol: CHAIN_CONFIG[chain].symbol };
  } else {
    const contract = new ethers.Contract(tokenAddress, ERC20_ABI, provider);
    let decimals = 18;
    try { decimals = await contract.decimals(); } catch (e) {}
    const parsed = ethers.parseUnits(amtStr, decimals);
    let gasLimit;
    try {
      gasLimit = await contract.estimateGas.transfer(toAddress, parsed, { from: fromAddress });
    } catch (e) {
      const populated = await contract.populateTransaction.transfer(toAddress, parsed);
      gasLimit = await provider.estimateGas({ ...populated, from: fromAddress });
    }
    const gasPrice = await provider.getGasPrice();
    const fee = Number(ethers.formatEther(gasLimit * gasPrice));
    return { gasLimit: gasLimit.toString(), gasPriceGwei: ethers.formatUnits(gasPrice, "gwei"), estimatedFeeNative: fee, nativeSymbol: CHAIN_CONFIG[chain].symbol };
  }
}

// ---------- TON: native send + jetton send helpers ----------

/**
 * sendTONNative:
 * - privateKeyHex is the ed25519 secretKey hex stored (decrypted)
 * - toAddress must be TON address string
 * - amountTon is string or number (TON units)
 */
async function sendTONNative(privateKeyHex, toAddress, amountTon) {
  if (!TonWeb) throw new Error("tonweb required");
  if (!CHAIN_CONFIG.ton.rpc) throw new Error("TON_RPC not configured");

  const tonweb = new TonWeb(tonwebProvider || new TonWeb.HttpProvider(CHAIN_CONFIG.ton.rpc));
  const secretKey = Buffer.from(privateKeyHex, "hex");
  const keyPair = TonWeb.utils.nacl.sign.keyPair.fromSecretKey(secretKey);
  // pick v3 wallet
  const WalletClass = TonWeb.wallet.all.v3R2 || TonWeb.wallet.all.v3 || TonWeb.wallet;
  const wallet = new WalletClass(tonweb.provider, { publicKey: keyPair.publicKey });
  const walletAddress = await wallet.getAddress();
  const seqno = (await wallet.methods.seqno().call()) || 0;
  const to = toAddress;
  const amountNano = TonWeb.utils.toNano(String(amountTon)); // returns BN or string
  // create transfer
  const transfer = wallet.methods.transfer({
    secretKey,
    toAddress: to,
    amount: amountNano,
    seqno
  });
  const result = await transfer.send();
  return result; // contains transaction info. Note: shape depends on provider; check receipt via explorer
}

/**
 * sendTonJetton:
 * - privateKeyHex: user's secretKey hex
 * - recipientTonAddress: string
 * - amount: number (human units)
 * - jettonMaster: jetton master contract address (jetton master)
 *
 * Implementation notes:
 * - Jetton architecture: a jetton master has per-holder jetton wallet contracts.
 * - We find/create sender's jetton wallet, then call transfer on it.
 *
 * This implementation uses TonWeb.token.jetton. It attempts to:
 *  - compute sender jetton wallet address
 *  - prepare transfer body payload
 *  - send internal message via wallet.transfer
 *
 * This is a non-trivial operation and MUST be tested on small amounts.
 */
function decimalToBigInt(value, decimals) {
  const s = String(value).trim();
  if (!/^\d+(\.\d+)?$/.test(s)) throw new Error("Invalid amount");
  const [whole, frac = ""] = s.split(".");
  const fracPadded = (frac + "0".repeat(decimals)).slice(0, decimals);
  return BigInt(whole + fracPadded);
}

async function getJettonBalanceNano(ownerAddress, jettonMaster) {
  if (!TonWeb) throw new Error("tonweb required");
  if (!CHAIN_CONFIG.ton.rpc) throw new Error("TON_RPC not configured");
  const tonweb = new TonWeb(tonwebProvider || new TonWeb.HttpProvider(CHAIN_CONFIG.ton.rpc));
  const JettonMinter = TonWeb.token?.jetton?.JettonMinter;
  const JettonWallet = TonWeb.token?.jetton?.JettonWallet;
  if (!JettonMinter || !JettonWallet) throw new Error("Jetton helpers not available in this TonWeb version");

  const minter = new JettonMinter(tonweb.provider, { address: jettonMaster });
  const ownerAddr = new TonWeb.utils.Address(ownerAddress);
  const jettonWalletAddress = await minter.getJettonWalletAddress(ownerAddr);
  const wallet = new JettonWallet(tonweb.provider, { address: jettonWalletAddress });
  const data = await wallet.getData();
  return BigInt(data.balance.toString());
}

async function askCenAI(prompt) {
  const key = process.env.OPENAI_API_KEY;
  if (!key) throw new Error("OpenAI key missing");
  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${key}` },
    body: JSON.stringify({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "You are Cen AI." },
        { role: "user", content: prompt }
      ],
      max_tokens: 600
    })
  });
  const j = await res.json();
  if (!j.choices || !j.choices[0]) throw new Error("OpenAI no response");
  return j.choices[0].message.content;
}

async function executeWhatsAppSend(user, s) {
  const chain = s.chain;
  const toAddr = s.recipient;
  if (!isValidChain(chain)) throw new Error("Unsupported chain");
  if (chain !== "ton" && (!toAddr || !ethers.isAddress(toAddr))) throw new Error("Invalid recipient address");
  if (chain === "ton" && !isValidTonAddress(toAddr)) throw new Error("Invalid TON address");

  if (chain === "ton") {
    const entry = user.wallets.get("ton");
    if (!entry) throw new Error("Sender has no TON wallet");
    const priv = decryptPrivateKey(entry.privateKeyEnc);
    if (!s.tokenAddress) {
      const balanceNano = await getTonNanoBalance(entry.address);
      const amountNano = decimalToBigInt(s.amount, 9);
      if (balanceNano !== null && balanceNano < (amountNano + TON_NATIVE_FEE_NANO)) {
        throw new Error("Insufficient TON balance to cover amount and fees");
      }
      const res = await sendTONNative(priv, toAddr, s.amount);
      return `✅ Sent ${s.amount} TON (native). Explorer: ${CHAIN_CONFIG.ton.explorer}${res?.transactionHash || ""}`;
    }

    const tonBalanceNano = await getTonNanoBalance(entry.address);
    const minTonNeeded = TON_JETTON_FORWARD_NANO + TON_JETTON_GAS_BUFFER_NANO;
    if (tonBalanceNano !== null && tonBalanceNano < minTonNeeded) {
      throw new Error("Insufficient TON balance to cover jetton transfer fees");
    }
    const jettonDecimals = await getJettonDecimals(s.tokenAddress);
    const jettonAmountSmallest = decimalToBigInt(s.amount, jettonDecimals);
    const jettonBalance = await getJettonBalanceNano(entry.address, s.tokenAddress);
    if (jettonBalance < jettonAmountSmallest) {
      throw new Error(`Insufficient ${s.tokenSymbol || "JETTON"} balance`);
    }
    await sendTonJetton(priv, toAddr, s.amount, s.tokenAddress);
    return `✅ Sent ${s.amount} ${s.tokenSymbol || "JETTON"} (TON). Explorer: ${CHAIN_CONFIG.ton.explorer}`;
  }

  // EVM native / ERC20
  const entry = user.wallets.get(chain);
  const pk = decryptPrivateKey(entry.privateKeyEnc);
  const provider = providers[chain];
  if (!provider) throw new Error("Provider not configured");
  if (!s.tokenAddress) {
    const wallet = new ethers.Wallet(pk, provider);
    const tx = await wallet.sendTransaction({ to: toAddr, value: ethers.parseEther(String(s.amount)) });
    const receipt = await tx.wait(CONFIRMATIONS);
    await Tx.create({ userId: user.telegramId || user.whatsappNumber, from: entry.address, to: toAddr, amount: String(s.amount), token: "NATIVE", txHash: tx.hash, chain, status: receipt?.status === 1 ? "confirmed" : "failed" });
    return `✅ Sent ${s.amount} ${CHAIN_CONFIG[chain].symbol}\nTx: ${tx.hash}\n${explorerLink(chain, tx.hash)}`;
  } else {
    const signer = new ethers.Wallet(pk, provider);
    const tokenContract = new ethers.Contract(s.tokenAddress, ERC20_ABI, signer);
    let decimals = 18;
    try { decimals = await tokenContract.decimals(); } catch (_) {}
    const parsed = ethers.parseUnits(String(s.amount), decimals);
    const tx = await tokenContract.transfer(toAddr, parsed);
    const receipt = await tx.wait(CONFIRMATIONS);
    await Tx.create({ userId: user.telegramId || user.whatsappNumber, from: entry.address, to: toAddr, amount: String(s.amount), token: s.tokenSymbol || "ERC20", txHash: tx.hash, chain, status: receipt?.status === 1 ? "confirmed" : "failed" });
    return `✅ Sent ${s.amount} ${s.tokenSymbol || "TOKEN"}\nTx: ${tx.hash}\n${explorerLink(chain, tx.hash)}`;
  }
}

async function sendTonJetton(privateKeyHex, recipientTonAddress, amount, jettonMaster) {
  if (!TonWeb) throw new Error("tonweb required");
  if (!CHAIN_CONFIG.ton.rpc) throw new Error("TON_RPC not configured");
  const tonweb = new TonWeb(tonwebProvider || new TonWeb.HttpProvider(CHAIN_CONFIG.ton.rpc));
  const nacl = TonWeb.utils.nacl;
  const secretKey = Buffer.from(privateKeyHex, "hex");
  const keyPair = TonWeb.utils.nacl.sign.keyPair.fromSecretKey(secretKey);
  // wallet
  const WalletClass = TonWeb.wallet.all.v3R2 || TonWeb.wallet.all.v3 || TonWeb.wallet;
  const wallet = new WalletClass(tonweb.provider, { publicKey: keyPair.publicKey });
  const senderAddress = (await wallet.getAddress()).toString(true, true, true);

  // Jetton helper (TonWeb has token.jetton)
  if (!TonWeb.token || !TonWeb.token.jetton) {
    throw new Error("TonWeb token.jetton helper not available in this tonweb version");
  }
  const JettonMinter = TonWeb.token.jetton.JettonMinter;
  const JettonWallet = TonWeb.token.jetton.JettonWallet;
  if (!JettonMinter || !JettonWallet) {
    throw new Error("Jetton helpers not available in this TonWeb version");
  }

  const minter = new JettonMinter(tonweb.provider, { address: jettonMaster });
  const senderJettonWalletAddress = await minter.getJettonWalletAddress(new TonWeb.utils.Address(senderAddress));
  const recipientJettonWalletAddress = await minter.getJettonWalletAddress(new TonWeb.utils.Address(recipientTonAddress));

  let decimals = 9;
  try { decimals = await getJettonDecimals(jettonMaster); } catch (_) {}

  const amountSmallest = decimalToBigInt(amount, decimals);

  // Build transfer body and send internal message via user's wallet
  try {
    const senderJettonWallet = new JettonWallet(tonweb.provider, { address: senderJettonWalletAddress });
    const transferBody = await senderJettonWallet.createTransferBody({
      jettonAmount: new TonWeb.utils.BN(amountSmallest.toString()),
      toAddress: recipientJettonWalletAddress,
      responseAddress: new TonWeb.utils.Address(senderAddress),
      forwardAmount: new TonWeb.utils.BN(0),
      forwardPayload: null
    });

    const wallet = new WalletClass(tonweb.provider, { publicKey: keyPair.publicKey });
    const seqno = (await wallet.methods.seqno().call()) || 0;
    const tx = await wallet.methods.transfer({
      secretKey,
      toAddress: senderJettonWalletAddress.toString(true, true, true),
      amount: new TonWeb.utils.BN(TON_JETTON_FORWARD_NANO.toString()),
      seqno,
      payload: transferBody
    }).send();
    return tx;
  } catch (innerErr) {
    throw new Error("Jetton transfer failed (detailed): " + (innerErr?.message || innerErr));
  }
}

// ---------- Swap & Bridge scaffolds (unchanged from prior) ----------
// (1inch, Wormhole placeholders) -- omitted here to keep file focused. They still exist in your project scaffold.

// ---------- Keyboards & commands ----------
function mainMenu() {
  return {
    reply_markup: {
      inline_keyboard: [
        [{ text: "🔐 My Wallet", callback_data: "wallet" }],
        [{ text: "💸 Send Funds", callback_data: "start_send" }],
        [{ text: "📥 Receive", callback_data: "receive" }],
        [{ text: "🔁 Swap", callback_data: "swap_menu" }],
        [{ text: "🌉 Bridge", callback_data: "bridge_menu" }],
        [{ text: "🧾 History", callback_data: "history" }],
        [{ text: "🧠 Ask Cen AI", callback_data: "ask_ai" }],
      ]
    }
  };
}
function chainSelectKeyboard(prefix = "chain_select:") {
  return { reply_markup: { inline_keyboard: SUPPORTED_CHAINS.map(c => [{ text: `${CHAIN_CONFIG[c].name} (${CHAIN_CONFIG[c].symbol})`, callback_data: `${prefix}${c}` }]) } };
}
function walletActionsKeyboard(chain = null) {
  if (!chain) return { reply_markup: { inline_keyboard: [[{ text: "Select Chain", callback_data: "select_chain" }]] } };
  const rows = [
    [{ text: "📋 Copy Address", callback_data: `copy_addr:${chain}` }, { text: "🔄 Refresh Balance", callback_data: `refresh_balance:${chain}` }],
    [{ text: "📷 View QR", callback_data: `view_qr:${chain}` }, { text: "🔁 Switch Chain", callback_data: "switch_chain" }]
  ];
  return { reply_markup: { inline_keyboard: rows } };
}

// ---------- Commands ----------
bot.onText(/\/start/, async (msg) => {
  try {
    await getOrCreateUser(msg.from);
    const welcome = `⚡ *Welcome to CenDeFi (crypto-only)*\nManage multi-chain wallets (Polygon, BSC, Base, Ethereum, TON) in chat.`;
    await bot.sendMessage(msg.chat.id, welcome, { parse_mode: "Markdown", ...mainMenu() });
  } catch (e) { console.error("/start err", e); sendSafeError(msg.chat.id); }
});

bot.onText(/\/menu/, (msg) => bot.sendMessage(msg.chat.id, "🔽 *CenDeFi Menu*", { parse_mode: "Markdown", ...mainMenu() }));

// /setpin
bot.onText(/\/setpin/, async (msg) => {
  try {
    const user = await getOrCreateUser(msg.from);
    const chatId = msg.chat.id;
    if (!user.pinHash) {
      const prompt = await bot.sendMessage(chatId, "🔐 Enter a new 4–6 digit PIN:\n⚠️ Do NOT share your PIN.", { reply_markup: { force_reply: true, selective: true } });
      pinSetSessions[String(msg.from.id)] = { stage: "enter", botPromptId1: prompt.message_id };
    } else {
      const prompt = await bot.sendMessage(chatId, "🔐 Enter your *current* PIN to change it:", { parse_mode: "Markdown", reply_markup: { force_reply: true, selective: true }});
      pinSetSessions[String(msg.from.id)] = { stage: "verify_old", botPromptId1: prompt.message_id };
    }
  } catch (e) { console.error("/setpin err", e); sendSafeError(msg.chat.id); }
});

// /createwallet
bot.onText(/\/createwallet/, async (msg) => {
  try {
    const user = await getOrCreateUser(msg.from);
    for (const chain of SUPPORTED_CHAINS) {
      await ensureChainWallet(user, chain).catch(err => console.warn("ensureChainWallet", chain, err?.message || err));
    }
    await bot.sendMessage(msg.chat.id, `✅ Wallets created for: ${SUPPORTED_CHAINS.map(c => CHAIN_CONFIG[c].name).join(", ")}`);
  } catch (e) { console.error("/createwallet err", e); sendSafeError(msg.chat.id); }
});

// /balance requires PIN
bot.onText(/\/balance/, async (msg) => {
  try { await requestPINForAction(String(msg.from.id), msg.chat.id, "view_balance"); } catch (e) { console.error("/balance err", e); sendSafeError(msg.chat.id); }
});

// /scantokens
bot.onText(/\/scantokens/, async (msg) => {
  try {
    const user = await getOrCreateUser(msg.from);
    const chain = user.preferredChain || SUPPORTED_CHAINS[0];
    await ensureChainWallet(user, chain);
    const entry = user.wallets.get(chain);
    const tokens = await scanTokensForAddress(chain, entry.address);
    if (!tokens.length) return bot.sendMessage(msg.chat.id, "No tokens detected (from curated list).");
    let out = `Tokens on ${CHAIN_CONFIG[chain].name}:\n\n`;
    tokens.forEach(t => out += `• ${t.symbol}: ${t.balance}\n`);
    await bot.sendMessage(msg.chat.id, out);
  } catch (e) { console.error("/scantokens err", e); sendSafeError(msg.chat.id); }
});

// /history
bot.onText(/\/history/, async (msg) => {
  try {
    const user = await getOrCreateUser(msg.from);
    const rows = await Tx.find({ userId: user.telegramId }).sort({ createdAt: -1 }).limit(12);
    if (!rows.length) return bot.sendMessage(msg.chat.id, "🧾 No transactions yet.");
    let out = "🧾 Recent Transactions:\n\n";
    rows.forEach(r => out += `• [${r.chain}] ${r.amount} → ${shortAddr(r.to)} - ${r.status}${r.txHash ? ` - ${r.txHash}` : ""}\n`);
    await bot.sendMessage(msg.chat.id, out);
  } catch (e) { console.error("/history err", e); sendSafeError(msg.chat.id); }
});

// ---------- Callback handler ----------
bot.on("callback_query", async (query) => {
  const chatId = query.message.chat.id;
  const from = query.from;
  const telegramId = String(from.id);
  const data = query.data;
  try { await bot.answerCallbackQuery(query.id); } catch (e) {}

  try {
    const user = await getOrCreateUser(from);

    // wallet overview
    if (data === "wallet") {
      const chain = user.preferredChain || SUPPORTED_CHAINS[0];
      await ensureChainWallet(user, chain);
      const entry = user.wallets.get(chain);
      const bal = await getChainBalance(user, chain).catch(() => "n/a");
      return bot.sendMessage(chatId, `🔐 *${CHAIN_CONFIG[chain].name} Wallet*\nAddress: \`${entry.address}\`\nBalance: *${bal}* ${CHAIN_CONFIG[chain].symbol}`, { parse_mode: "Markdown", ...walletActionsKeyboard(chain) });
    }

    // start send: chain select
    if (data === "start_send") {
      return bot.sendMessage(chatId, "Select chain to send from:", chainSelectKeyboard("send_chain:"));
    }

    // receive -> show QR
    if (data === "receive") {
      return bot.sendMessage(chatId, "Select chain to receive on:", chainSelectKeyboard("receive_chain:"));
    }

    // swap menu / bridge menu scaffolds omitted for brevity
    if (data === "swap_menu") { return bot.sendMessage(chatId, "Swap coming soon — select chain to swap on:", chainSelectKeyboard("swap_chain:")); }
    if (data === "bridge_menu") { return bot.sendMessage(chatId, "Bridge coming soon — select source chain:", chainSelectKeyboard("bridge_from:")); }

    // chain select generic
    if (data.startsWith("chain_select:")) {
      const chain = data.split(":")[1];
      if (!isValidChain(chain)) return bot.sendMessage(chatId, "Unsupported chain.");
      await ensureChainWallet(user, chain);
      const entry = user.wallets.get(chain);
      const bal = await getChainBalance(user, chain).catch(() => "n/a");
      return bot.sendMessage(chatId, `*${CHAIN_CONFIG[chain].name}*\nAddress: \`${entry.address}\`\nBalance: *${bal}* ${CHAIN_CONFIG[chain].symbol}`, { parse_mode: "Markdown", ...walletActionsKeyboard(chain) });
    }

    // send_chain: require PIN then start send flow
    if (data.startsWith("send_chain:")) {
      const chain = data.split(":")[1];
      if (!isValidChain(chain)) return bot.sendMessage(chatId, "Unsupported chain.");
      return await requestPINForAction(telegramId, chatId, "start_send", { chain });
    }

    // receive_chain
    if (data.startsWith("receive_chain:")) {
      const chain = data.split(":")[1];
      if (!isValidChain(chain)) return bot.sendMessage(chatId, "Unsupported chain.");
      await ensureChainWallet(user, chain);
      const entry = user.wallets.get(chain);
      const qrUrl = `https://chart.googleapis.com/chart?chs=300x300&cht=qr&chl=${encodeURIComponent(entry.address)}`;
      await bot.sendMessage(chatId, `📥 *Receive ${CHAIN_CONFIG[chain].symbol}*\n\`${entry.address}\``, { parse_mode: "Markdown" });
      return bot.sendPhoto(chatId, qrUrl);
    }

    // copy / refresh
    if (data.startsWith("copy_addr:")) {
      const chain = data.split(":")[1];
      if (!isValidChain(chain)) return bot.sendMessage(chatId, "Unsupported chain.");
      const entry = user.wallets.get(chain);
      if (!entry) return bot.sendMessage(chatId, "No wallet for that chain.");
      return bot.sendMessage(chatId, `📋 Address:\n\`${entry.address}\``, { parse_mode: "Markdown" });
    }
    if (data.startsWith("refresh_balance:")) {
      const chain = data.split(":")[1];
      if (!isValidChain(chain)) return bot.sendMessage(chatId, "Unsupported chain.");
      return await requestPINForAction(telegramId, chatId, "view_balance", { chain });
    }

    // switch chain
    if (data === "switch_chain") {
      return bot.sendMessage(chatId, "Select your preferred chain:", chainSelectKeyboard("set_pref:"));
    }
    if (data.startsWith("set_pref:")) {
      const chain = data.split(":")[1];
      if (!isValidChain(chain)) return bot.sendMessage(chatId, "Unsupported chain.");
      user.preferredChain = chain;
      await user.save();
      return bot.sendMessage(chatId, `✅ Preferred chain set to ${CHAIN_CONFIG[chain].name}`);
    }

    // Send Confirm / Cancel
    if (data === "SEND_CANCEL") {
      delete sendState[telegramId];
      return bot.sendMessage(chatId, "❌ Send cancelled.");
    }
    if (data === "SEND_CONFIRM") {
      const s = sendState[telegramId];
      if (!s || s.step !== "confirm") return bot.sendMessage(chatId, "No active send session.");
      const chain = s.chain;
      const sender = user;
      let toAddr = s.recipient;
      let recipientUser = null;
      if (toAddr && toAddr.startsWith("@")) {
        const uname = toAddr.slice(1).toLowerCase();
        recipientUser = await User.findOne({ username: uname });
        if (!recipientUser) { delete sendState[telegramId]; return bot.sendMessage(chatId, "❌ Recipient not found."); }
        const rEntry = recipientUser.wallets.get(chain);
        if (!rEntry || !rEntry.address) { delete sendState[telegramId]; return bot.sendMessage(chatId, "❌ Recipient has no wallet on this chain."); }
        toAddr = rEntry.address;
      }
      // Validate non-TON addresses with ethers.isAddress
      if (chain !== "ton" && (!toAddr || !ethers.isAddress(toAddr))) { delete sendState[telegramId]; return bot.sendMessage(chatId, "❌ Invalid recipient address."); }
      if (chain === "ton" && !isValidTonAddress(toAddr)) { delete sendState[telegramId]; return bot.sendMessage(chatId, "❌ Invalid TON address."); }

      try {
        if (chain === "ton") {
          // TON send (native or jetton)
          const entry = sender.wallets.get("ton");
          if (!entry) { delete sendState[telegramId]; return bot.sendMessage(chatId, "❌ Sender has no TON wallet."); }
          const privEnc = entry.privateKeyEnc;
          const priv = decryptPrivateKey(privEnc); // hex secretKey
          if (!s.tokenAddress) {
            // native TON send
            try {
              const balanceNano = await getTonNanoBalance(entry.address);
              const amountNano = decimalToBigInt(s.amount, 9);
              if (balanceNano !== null && balanceNano < (amountNano + TON_NATIVE_FEE_NANO)) {
                delete sendState[telegramId];
                return bot.sendMessage(chatId, "❌ Insufficient TON balance to cover amount and fees.");
              }
              const res = await sendTONNative(priv, toAddr, s.amount);
              delete sendState[telegramId];
              // Note: Ton transfer result format depends on provider; use explorer to view.
              await bot.sendMessage(chatId, `✅ Sent ${s.amount} TON (native). Check explorer: ${CHAIN_CONFIG.ton.explorer}${res?.transactionHash || ""}`);
              if (recipientUser) await bot.sendMessage(recipientUser.telegramId, `💸 You received ${s.amount} TON from @${sender.username || sender.telegramId}`);
              return;
            } catch (err) {
              console.error("TON native send error:", err);
              delete sendState[telegramId];
              return sendSafeError(chatId);
            }
          } else {
            // Jetton transfer
            try {
              const tonBalanceNano = await getTonNanoBalance(entry.address);
              const minTonNeeded = TON_JETTON_FORWARD_NANO + TON_JETTON_GAS_BUFFER_NANO;
              if (tonBalanceNano !== null && tonBalanceNano < minTonNeeded) {
                delete sendState[telegramId];
                return bot.sendMessage(chatId, "❌ Insufficient TON balance to cover jetton transfer fees.");
              }
              const jettonDecimals = await getJettonDecimals(s.tokenAddress);
              const jettonAmountSmallest = decimalToBigInt(s.amount, jettonDecimals);
              const jettonBalance = await getJettonBalanceNano(entry.address, s.tokenAddress);
              if (jettonBalance < jettonAmountSmallest) {
                delete sendState[telegramId];
                return bot.sendMessage(chatId, `❌ Insufficient ${s.tokenSymbol || "JETTON"} balance.`);
              }
              const jettonMaster = s.tokenAddress; // Jetton master contract (EQ... address)
              const res = await sendTonJetton(priv, toAddr, s.amount, jettonMaster);
              delete sendState[telegramId];
              await bot.sendMessage(chatId, `✅ Sent ${s.amount} ${s.tokenSymbol || "JETTON"} (TON). Check explorer: ${CHAIN_CONFIG.ton.explorer} (use tx id from provider)`);
              if (recipientUser) await bot.sendMessage(recipientUser.telegramId, `💸 You received ${s.amount} ${s.tokenSymbol || "JETTON"} from @${sender.username || sender.telegramId}`);
              return;
            } catch (err) {
              console.error("TON jetton send error:", err);
              delete sendState[telegramId];
              return bot.sendMessage(chatId, `❌ Jetton transfer failed: ${err?.message || err}`);
            }
          }
        }

        // EVM send flow (native or token)
        if (!s.tokenAddress) {
          const entry = sender.wallets.get(chain);
          const pk = decryptPrivateKey(entry.privateKeyEnc);
          const provider = providers[chain];
          const wallet = new ethers.Wallet(pk, provider);
          const tx = await wallet.sendTransaction({ to: toAddr, value: ethers.parseEther(String(s.amount)) });
          const receipt = await tx.wait(CONFIRMATIONS);
          const txDoc = await Tx.create({ userId: sender.telegramId, from: entry.address, to: toAddr, amount: String(s.amount), token: "NATIVE", txHash: tx.hash, chain, status: receipt?.status === 1 ? "confirmed" : "failed" });
          delete sendState[telegramId];
          await bot.sendMessage(chatId, `✅ Sent ${s.amount} ${CHAIN_CONFIG[chain].symbol}\nTx: \`${txDoc.txHash}\`\n${explorerLink(chain, txDoc.txHash)}`, { parse_mode: "Markdown" });
          if (recipientUser) await bot.sendMessage(recipientUser.telegramId, `💸 You received ${s.amount} ${CHAIN_CONFIG[chain].symbol} from @${sender.username || sender.telegramId}`);
          return;
        } else {
          const entry = sender.wallets.get(chain);
          const pk = decryptPrivateKey(entry.privateKeyEnc);
          const provider = providers[chain];
          const signer = new ethers.Wallet(pk, provider);
          const tokenContract = new ethers.Contract(s.tokenAddress, ERC20_ABI, signer);
          let decimals = 18;
          try { decimals = await tokenContract.decimals(); } catch (e) {}
          const parsed = ethers.parseUnits(String(s.amount), decimals);
          const tx = await tokenContract.transfer(toAddr, parsed);
          const receipt = await tx.wait(CONFIRMATIONS);
          const txDoc = await Tx.create({ userId: sender.telegramId, from: entry.address, to: toAddr, amount: String(s.amount), token: s.tokenSymbol || "ERC20", txHash: tx.hash, chain, status: receipt?.status === 1 ? "confirmed" : "failed" });
          delete sendState[telegramId];
          await bot.sendMessage(chatId, `✅ Sent ${s.amount} ${s.tokenSymbol || "TOKEN"}\nTx: \`${tx.hash}\``, { parse_mode: "Markdown" });
          if (recipientUser) await bot.sendMessage(recipientUser.telegramId, `💸 You received ${s.amount} ${s.tokenSymbol || "TOKEN"} from @${sender.username || sender.telegramId}`);
          return;
        }
      } catch (err) {
        console.error("SEND_CONFIRM error:", err);
        delete sendState[telegramId];
        return sendSafeError(chatId);
      }
    }

    // Ask AI
    if (data === "ask_ai") {
      user.state = "awaiting_ai_query";
      await user.save();
      return bot.sendMessage(chatId, "🧠 Ask Cen AI — type your question now.");
    }

    console.debug("Unhandled callback:", data);
  } catch (e) {
    console.error("callback handler error:", e);
    sendSafeError(chatId);
  }
});

// ---------- Message handler ----------
bot.on("message", async (msg) => {
  const chatId = msg.chat.id;
  const from = msg.from;
  const telegramId = String(from.id);
  const text = msg.text ? msg.text.trim() : "";
  if (!text) return;

  try {
    // PIN entry handling
    if (pinSessions[telegramId]) {
      const session = pinSessions[telegramId];
      if (!/^\d{4,6}$/.test(text)) return bot.sendMessage(chatId, "❌ PIN must be 4–6 digits. Try again.");
      const user = await User.findOne({ telegramId });
      if (!user) { clearPinSession(telegramId); return bot.sendMessage(chatId, "User missing."); }
      if (user.pinLockedUntil && new Date(user.pinLockedUntil) > new Date()) {
        clearPinSession(telegramId);
        const mins = Math.ceil((new Date(user.pinLockedUntil) - Date.now())/60000);
        return bot.sendMessage(chatId, `🔒 Locked. Try again in ${mins} minutes.`);
      }
      if (hashPIN(text) !== user.pinHash) {
        user.pinAttempts = (user.pinAttempts || 0) + 1;
        if (user.pinAttempts >= 5) {
          user.pinLockedUntil = new Date(Date.now() + 5*60*1000); // 5 minutes
          user.pinAttempts = 0;
          await user.save();
          clearPinSession(telegramId);
          return bot.sendMessage(chatId, "🔒 Too many wrong attempts. Locked for 5 minutes.");
        } else {
          await user.save();
          return bot.sendMessage(chatId, "❌ Incorrect PIN. Try again.");
        }
      }
      // PIN correct
      user.pinAttempts = 0;
      await user.save();
      try { await bot.deleteMessage(chatId, msg.message_id); } catch (_) {}
      try { if (session.botPromptMessageId) await bot.deleteMessage(chatId, session.botPromptMessageId); } catch (_) {}
      const action = session.action;
      const params = session.params || {};
      clearPinSession(telegramId);

      if (action === "view_balance") {
        if (params.chain) {
          await ensureChainWallet(user, params.chain);
          const bal = await getChainBalance(user, params.chain).catch(() => "n/a");
          return bot.sendMessage(chatId, `💰 *${CHAIN_CONFIG[params.chain].name}*: *${bal}* ${CHAIN_CONFIG[params.chain].symbol}`, { parse_mode: "Markdown" });
        } else {
          let out = "💰 *Balances*\n\n";
          for (const chain of SUPPORTED_CHAINS) {
            try {
              await ensureChainWallet(user, chain);
              const bal = await getChainBalance(user, chain).catch(() => "n/a");
              out += `• ${CHAIN_CONFIG[chain].name}: *${bal}* ${CHAIN_CONFIG[chain].symbol}\n`;
            } catch (e) { out += `• ${CHAIN_CONFIG[chain].name}: *n/a*\n`; }
          }
          return bot.sendMessage(chatId, out, { parse_mode: "Markdown" });
        }
      }

      if (action === "start_send") {
        const chain = params.chain || user.preferredChain || SUPPORTED_CHAINS[0];
        sendState[telegramId] = { chain, step: "askRecipient" };
        return bot.sendMessage(chatId, `💸 *Send (${CHAIN_CONFIG[chain].name})* — Enter recipient @username or wallet address:`, { parse_mode: "Markdown" });
      }

      return bot.sendMessage(chatId, "✅ PIN accepted.");
    }

    // /setpin interactive flow
    if (pinSetSessions[telegramId]) {
      const session = pinSetSessions[telegramId];
      const user = await getOrCreateUser(from);
      if (session.stage === "verify_old") {
        if (!/^\d{4,6}$/.test(text)) return bot.sendMessage(chatId, "❌ PIN must be 4–6 digits.");
        if (hashPIN(text) !== user.pinHash) return bot.sendMessage(chatId, "❌ Incorrect PIN.");
        session.stage = "enter";
        pinSetSessions[telegramId] = session;
        try { await bot.deleteMessage(chatId, msg.message_id); } catch (_) {}
        const p2 = await bot.sendMessage(chatId, "✅ Verified. Enter your new 4–6 digit PIN:", { reply_markup: { force_reply: true, selective: true }});
        session.botPromptId2 = p2.message_id;
        return;
      }
      if (session.stage === "enter") {
        if (!/^\d{4,6}$/.test(text)) return bot.sendMessage(chatId, "❌ PIN must be 4–6 digits.");
        session.tempPin = text;
        session.stage = "confirm";
        pinSetSessions[telegramId] = session;
        const p3 = await bot.sendMessage(chatId, "🔐 Confirm new PIN (re-enter):", { reply_markup: { force_reply: true, selective: true }});
        session.botPromptId3 = p3.message_id;
        return;
      }
      if (session.stage === "confirm") {
        if (!session.tempPin || text !== session.tempPin) {
          delete pinSetSessions[telegramId];
          return bot.sendMessage(chatId, "❌ PINs did not match. Run /setpin again.");
        }
        user.pinHash = hashPIN(text);
        user.pinAttempts = 0;
        user.pinLockedUntil = null;
        await user.save();
        try { if (session.botPromptId1) await bot.deleteMessage(chatId, session.botPromptId1); } catch (_) {}
        try { if (session.botPromptId2) await bot.deleteMessage(chatId, session.botPromptId2); } catch (_) {}
        try { await bot.deleteMessage(chatId, msg.message_id); } catch (_) {}
        delete pinSetSessions[telegramId];
        return bot.sendMessage(chatId, "✅ PIN set successfully. Keep it secret.");
      }
    }

    // other interactive flows
    const user = await getOrCreateUser(from);

    // AI flow
    if (user.state === "awaiting_ai_query") {
      user.state = null; await user.save();
      try {
        const response = await askCenAI(text);
        return bot.sendMessage(chatId, `🧠 Cen AI:\n\n${response}`);
      } catch (e) { console.error("AI error", e); return sendSafeError(chatId); }
    }

    // Send flow: recipient -> token/native -> amount -> gas estimate -> confirm
    const s = sendState[telegramId];
    if (s && s.step === "askRecipient") {
      const input = text;
      if (input.startsWith("@")) {
        const uname = input.slice(1).toLowerCase();
        const target = await User.findOne({ username: uname });
        if (!target) return bot.sendMessage(chatId, "❌ Username not found.");
        const rEntry = target.wallets.get(s.chain);
        if (!rEntry || !rEntry.address) return bot.sendMessage(chatId, "❌ Recipient has no wallet on this chain.");
        s.recipient = `@${uname}`;
        s.step = "askTokenChoice";
        return bot.sendMessage(chatId, "Do you want to send `native` or `token`? Reply `native` or `token`.");
      } else {
        if (s.chain !== "ton" && !ethers.isAddress(input)) return bot.sendMessage(chatId, "❌ Invalid address.");
        // TON addresses are flexible; basic check: non-empty
        if (s.chain === "ton" && !isValidTonAddress(input)) return bot.sendMessage(chatId, "❌ Invalid TON address.");
        s.recipient = input;
        s.step = "askTokenChoice";
        return bot.sendMessage(chatId, "Do you want to send `native` or `token`? Reply `native` or `token`.");
      }
    }

    if (s && s.step === "askTokenChoice") {
      const val = text.toLowerCase();
      if (val === "native") {
        s.tokenAddress = null; s.tokenSymbol = CHAIN_CONFIG[s.chain].symbol; s.step = "askAmount"; return bot.sendMessage(chatId, `Enter amount in ${s.tokenSymbol} (e.g., 0.1)` );
      }
      if (val === "token") {
        const tokens = TOKEN_LIST[s.chain] || [];
        const list = tokens.map((t,i)=> `${i+1}. ${t.symbol}${t.address?` (${t.address})`:" (native)"}`).join("\n");
        s.step = "chooseToken";
        return bot.sendMessage(chatId, `Select token by number OR paste token contract address / jetton address:\n\n${list}`);
      }
      return bot.sendMessage(chatId, "Reply with `native` or `token`.");
    }

    if (s && s.step === "chooseToken") {
      const tokens = TOKEN_LIST[s.chain] || [];
      const n = parseInt(text);
      if (!isNaN(n) && n>=1 && n<=tokens.length) {
        const t = tokens[n-1];
        s.tokenAddress = t.address; s.tokenSymbol = t.symbol; s.step = "askAmount";
        return bot.sendMessage(chatId, `Enter amount in ${s.tokenSymbol} (e.g., 10.5)`);
      }
      // pasted address / jetton
      if (s.chain !== "ton" && ethers.isAddress(text)) {
        s.tokenAddress = text;
        try {
          const provider = providers[s.chain];
          const contract = new ethers.Contract(text, ERC20_ABI, provider);
          s.tokenSymbol = await contract.symbol().catch(()=> "TOKEN");
        } catch (e) { s.tokenSymbol = "TOKEN"; }
        s.step = "askAmount";
        return bot.sendMessage(chatId, `Enter amount in ${s.tokenSymbol} (e.g., 10.5)`);
      }
      if (s.chain === "ton") {
        if (!isValidTonAddress(text)) return bot.sendMessage(chatId, "❌ Invalid jetton address.");
        s.tokenAddress = text; s.tokenSymbol = "JETTON"; s.step = "askAmount";
        return bot.sendMessage(chatId, `Enter amount in ${s.tokenSymbol} (e.g., 10.5)`);
      }
      return bot.sendMessage(chatId, "Invalid input. Enter token number or paste contract address.");
    }

    if (s && s.step === "askAmount") {
      const amt = parseFloat(text);
      if (isNaN(amt) || amt <= 0) return bot.sendMessage(chatId, "❌ Invalid amount.");
      s.amount = amt;
      // resolve recipient address for gas estimate
      let resolvedTo = null;
      if (s.recipient.startsWith("@")) {
        const uname = s.recipient.slice(1).toLowerCase();
        const target = await User.findOne({ username: uname });
        if (!target) return bot.sendMessage(chatId, "❌ Recipient not found.");
        const rEntry = target.wallets.get(s.chain);
        if (!rEntry || !rEntry.address) return bot.sendMessage(chatId, "❌ Recipient has no wallet on this chain.");
        resolvedTo = rEntry.address;
      } else resolvedTo = s.recipient;

      // ensure sender wallet
      await ensureChainWallet(user, s.chain);
      const senderEntry = user.wallets.get(s.chain);
      const fromAddr = senderEntry.address;

      // estimate gas / fees
      try {
        const gasInfo = await estimateGasForTransfer(s.chain, fromAddr, resolvedTo, s.amount, s.tokenAddress);
        s.gasInfo = gasInfo;
        s.step = "confirm";
        const summary = `🚀 *Summary*\nChain: *${CHAIN_CONFIG[s.chain].name}*\nRecipient: \`${s.recipient}\`\nAmount: *${s.amount}* ${s.tokenSymbol}\n\n⛽ *Estimated fee*: *${gasInfo.estimatedFeeNative}* ${gasInfo.nativeSymbol} (Gas Limit: ${gasInfo.gasLimit}, Gas Price: ${gasInfo.gasPriceGwei} Gwei)\n\nPress Confirm to send.`;
        return bot.sendMessage(chatId, summary, { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "✅ Confirm", callback_data: "SEND_CONFIRM" }, { text: "❌ Cancel", callback_data: "SEND_CANCEL" }]] }});
      } catch (e) {
        console.error("estimateGas error", e);
        return bot.sendMessage(chatId, "❌ Failed to estimate gas. Try again later.");
      }
    }

    // fallback help
    if (/^\/help$/i.test(text)) {
      return bot.sendMessage(chatId, "Use /menu. Commands: /createwallet /balance /history /setpin /scantokens /help");
    }

  } catch (err) {
    console.error("message handler error", err);
    return sendSafeError(chatId);
  }
});

// ---------- Express health ----------
// ---------- WhatsApp webhook (reuses wallet helpers) ----------
async function sendWhatsAppText(to, message) {
  const phoneId = process.env.WHATSAPP_PHONE_ID;
  const token = process.env.WHATSAPP_TOKEN;
  if (!phoneId || !token) throw new Error("Missing WHATSAPP_PHONE_ID or WHATSAPP_TOKEN");
  const url = `https://graph.facebook.com/v16.0/${phoneId}/messages`;
  const body = {
    messaging_product: "whatsapp",
    to,
    text: { body: message }
  };
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify(body)
  });
  return r.json();
}

async function sendWhatsAppMenu(to) {
  const phoneId = process.env.WHATSAPP_PHONE_ID;
  const token = process.env.WHATSAPP_TOKEN;
  if (!phoneId || !token) throw new Error("Missing WHATSAPP_PHONE_ID or WHATSAPP_TOKEN");
  const url = `https://graph.facebook.com/v16.0/${phoneId}/messages`;
  const body = {
    messaging_product: "whatsapp",
    to,
    type: "interactive",
    interactive: {
      type: "list",
      header: { type: "text", text: "CenDeFi Menu" },
      body: { text: "Choose an action:" },
      footer: { text: "Tip: You can still type commands." },
      action: {
        button: "Open Menu",
        sections: [
          {
            title: "Wallet",
            rows: [
              { id: "menu_createwallet", title: "Create Wallets", description: "Create wallets on supported chains" },
              { id: "menu_balance", title: "Balance", description: "Check balance on a chain" },
              { id: "menu_address", title: "Address", description: "Get your receive address" }
            ]
          },
          {
            title: "Send",
            rows: [
              { id: "menu_send", title: "Send Funds", description: "Choose chain then send" },
              { id: "menu_send_polygon", title: "Send on Polygon", description: "MATIC / tokens" },
              { id: "menu_send_bsc", title: "Send on BSC", description: "BNB / tokens" },
              { id: "menu_send_base", title: "Send on Base", description: "ETH / tokens" },
              { id: "menu_send_ethereum", title: "Send on Ethereum", description: "ETH / tokens" },
              { id: "menu_send_ton", title: "Send on TON", description: "TON / jettons" },
              { id: "menu_setpin", title: "Set PIN", description: "Protect sends with a PIN" }
            ]
          },
          {
            title: "AI",
            rows: [
              { id: "menu_ask", title: "Ask Cen AI", description: "Ask a question" }
            ]
          }
        ]
      }
    }
  };
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify(body)
  });
  return r.json();
}

async function sendWhatsAppButtons(to, bodyText, buttons) {
  const phoneId = process.env.WHATSAPP_PHONE_ID;
  const token = process.env.WHATSAPP_TOKEN;
  if (!phoneId || !token) throw new Error("Missing WHATSAPP_PHONE_ID or WHATSAPP_TOKEN");
  const url = `https://graph.facebook.com/v16.0/${phoneId}/messages`;
  const body = {
    messaging_product: "whatsapp",
    to,
    type: "interactive",
    interactive: {
      type: "button",
      body: { text: bodyText },
      action: {
        buttons: buttons.map(b => ({ type: "reply", reply: { id: b.id, title: b.title } }))
      }
    }
  };
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify(body)
  });
  return r.json();
}

async function sendWhatsAppMenuButtons(to) {
  return sendWhatsAppButtons(to, "Quick actions:", [
    { id: "menu_createwallet", title: "Create Wallet" },
    { id: "menu_balance", title: "Balance" },
    { id: "menu_address", title: "Address" }
  ]);
}

async function sendWhatsAppChainPicker(to) {
  await sendWhatsAppButtons(to, "Pick a chain to send from:", [
    { id: "menu_send_polygon", title: "Polygon" },
    { id: "menu_send_bsc", title: "BSC" },
    { id: "menu_send_base", title: "Base" }
  ]);
  return sendWhatsAppButtons(to, "More chains:", [
    { id: "menu_send_ethereum", title: "Ethereum" },
    { id: "menu_send_ton", title: "TON" },
    { id: "menu_send", title: "Use Default" }
  ]);
}

function mapWhatsAppMenuIdToText(id) {
  switch (id) {
    case "menu_createwallet": return "createwallet";
    case "menu_balance": return "balance";
    case "menu_address": return "address";
    case "menu_send": return "send";
    case "menu_send_polygon": return "send polygon";
    case "menu_send_bsc": return "send bsc";
    case "menu_send_base": return "send base";
    case "menu_send_ethereum": return "send ethereum";
    case "menu_send_ton": return "send ton";
    case "menu_setpin": return "setpin";
    case "menu_ask": return "ask";
    default: return null;
  }
}

async function handleWhatsAppText(from, text) {
  const user = await getOrCreateWhatsAppUser(from);
  const raw = (text || "").trim();
  if (!raw) return;
  const lower = raw.toLowerCase();

  // PIN set flow (WhatsApp)
  if (pinSetSessionsWA[from]) {
    const session = pinSetSessionsWA[from];
    if (session.stage === "verify_old") {
      if (!/^\d{4,6}$/.test(raw)) return sendWhatsAppText(from, "PIN must be 4-6 digits.");
      if (hashPIN(raw) !== user.pinHash) return sendWhatsAppText(from, "Incorrect PIN.");
      session.stage = "enter";
      pinSetSessionsWA[from] = session;
      return sendWhatsAppText(from, "Verified. Enter your new 4-6 digit PIN:");
    }
    if (session.stage === "enter") {
      if (!/^\d{4,6}$/.test(raw)) return sendWhatsAppText(from, "PIN must be 4-6 digits.");
      session.tempPin = raw;
      session.stage = "confirm";
      pinSetSessionsWA[from] = session;
      return sendWhatsAppText(from, "Confirm new PIN (re-enter):");
    }
    if (session.stage === "confirm") {
      if (!session.tempPin || raw !== session.tempPin) {
        delete pinSetSessionsWA[from];
        return sendWhatsAppText(from, "PINs did not match. Send 'setpin' again.");
      }
      user.pinHash = hashPIN(raw);
      user.pinAttempts = 0;
      user.pinLockedUntil = null;
      await user.save();
      delete pinSetSessionsWA[from];
      return sendWhatsAppText(from, "PIN set successfully.");
    }
  }

  // PIN entry flow (WhatsApp)
  if (pinSessionsWA[from]) {
    const session = pinSessionsWA[from];
    if (!/^\d{4,6}$/.test(raw)) return sendWhatsAppText(from, "PIN must be 4-6 digits.");
    if (user.pinLockedUntil && new Date(user.pinLockedUntil) > new Date()) {
      delete pinSessionsWA[from];
      const mins = Math.ceil((new Date(user.pinLockedUntil) - Date.now())/60000);
      return sendWhatsAppText(from, `Locked. Try again in ${mins} minutes.`);
    }
    if (hashPIN(raw) !== user.pinHash) {
      user.pinAttempts = (user.pinAttempts || 0) + 1;
      if (user.pinAttempts >= 5) {
        user.pinLockedUntil = new Date(Date.now() + 5*60*1000);
        user.pinAttempts = 0;
        await user.save();
        delete pinSessionsWA[from];
        return sendWhatsAppText(from, "Too many wrong attempts. Locked for 5 minutes.");
      } else {
        await user.save();
        return sendWhatsAppText(from, "Incorrect PIN. Try again.");
      }
    }
    user.pinAttempts = 0;
    await user.save();
    delete pinSessionsWA[from];

    if (session.action === "wa_send_confirm") {
      const s = sendStateWA[from];
      if (!s) return sendWhatsAppText(from, "No active send session.");
      try {
        const msg = await executeWhatsAppSend(user, s);
        delete sendStateWA[from];
        return sendWhatsAppText(from, msg);
      } catch (e) {
        delete sendStateWA[from];
        return sendWhatsAppText(from, `Send failed: ${e?.message || e}`);
      }
    }

    return sendWhatsAppText(from, "PIN accepted.");
  }

  // Send flow (WhatsApp)
  if (sendStateWA[from]) {
    const s = sendStateWA[from];
    if (s.step === "askRecipient") {
      if (s.chain !== "ton" && !ethers.isAddress(raw)) return sendWhatsAppText(from, "Invalid address.");
      if (s.chain === "ton" && !isValidTonAddress(raw)) return sendWhatsAppText(from, "Invalid TON address.");
      s.recipient = raw;
      s.step = "askTokenChoice";
      return sendWhatsAppText(from, "Do you want to send 'native' or 'token'? Reply native or token.");
    }
    if (s.step === "askTokenChoice") {
      if (lower === "native") {
        s.tokenAddress = null;
        s.tokenSymbol = CHAIN_CONFIG[s.chain].symbol;
        s.step = "askAmount";
        return sendWhatsAppText(from, `Enter amount in ${s.tokenSymbol} (e.g., 0.1)`);
      }
      if (lower === "token") {
        const tokens = TOKEN_LIST[s.chain] || [];
        const list = tokens.map((t,i)=> `${i+1}. ${t.symbol}${t.address?` (${t.address})`:" (native)"}`).join("\\n");
        s.step = "chooseToken";
        return sendWhatsAppText(from, `Select token by number OR paste token contract / jetton address:\\n\\n${list}`);
      }
      return sendWhatsAppText(from, "Reply with native or token.");
    }
    if (s.step === "chooseToken") {
      const tokens = TOKEN_LIST[s.chain] || [];
      const n = parseInt(raw, 10);
      if (!isNaN(n) && n>=1 && n<=tokens.length) {
        const t = tokens[n-1];
        s.tokenAddress = t.address;
        s.tokenSymbol = t.symbol;
        s.step = "askAmount";
        return sendWhatsAppText(from, `Enter amount in ${s.tokenSymbol} (e.g., 10.5)`);
      }
      if (s.chain !== "ton" && ethers.isAddress(raw)) {
        s.tokenAddress = raw;
        try {
          const provider = providers[s.chain];
          const contract = new ethers.Contract(raw, ERC20_ABI, provider);
          s.tokenSymbol = await contract.symbol().catch(()=> "TOKEN");
        } catch (_) { s.tokenSymbol = "TOKEN"; }
        s.step = "askAmount";
        return sendWhatsAppText(from, `Enter amount in ${s.tokenSymbol} (e.g., 10.5)`);
      }
      if (s.chain === "ton") {
        if (!isValidTonAddress(raw)) return sendWhatsAppText(from, "Invalid jetton address.");
        s.tokenAddress = raw;
        s.tokenSymbol = "JETTON";
        s.step = "askAmount";
        return sendWhatsAppText(from, `Enter amount in ${s.tokenSymbol} (e.g., 10.5)`);
      }
      return sendWhatsAppText(from, "Invalid input. Enter token number or paste contract address.");
    }
    if (s.step === "askAmount") {
      const amt = parseFloat(raw);
      if (isNaN(amt) || amt <= 0) return sendWhatsAppText(from, "Invalid amount.");
      s.amount = amt;
      s.step = "confirm";
      const gasInfo = await estimateGasForTransfer(s.chain, "0x0", "0x0", s.amount, s.tokenAddress).catch(() => null);
      const feeLine = gasInfo ? `Estimated fee: ${gasInfo.estimatedFeeNative} ${gasInfo.nativeSymbol}` : "Estimated fee: n/a";
      await sendWhatsAppButtons(from, `Summary\nChain: ${CHAIN_CONFIG[s.chain].name}\nRecipient: ${s.recipient}\nAmount: ${s.amount} ${s.tokenSymbol}\n${feeLine}`, [
        { id: "wa_send_confirm", title: "Confirm" },
        { id: "wa_send_cancel", title: "Cancel" }
      ]);
      return sendWhatsAppText(from, "Tap a button: Confirm or Cancel.");
    }
    if (s.step === "confirm") {
      if (lower === "cancel") {
        delete sendStateWA[from];
        return sendWhatsAppText(from, "Send cancelled.");
      }
      if (lower === "confirm") {
        return requestPINForActionWhatsApp(from, "wa_send_confirm", {});
      }
      return sendWhatsAppText(from, "Reply CONFIRM to send or CANCEL to stop.");
    }
  }

  if (lower === "help" || lower === "menu") {
    await sendWhatsAppMenu(from);
    await sendWhatsAppMenuButtons(from);
    return sendWhatsAppText(from, "Commands: createwallet | balance [chain] | address [chain] | send [chain] | setpin | ask <question>");
  }

  if (lower === "setpin") {
    if (!user.pinHash) {
      pinSetSessionsWA[from] = { stage: "enter" };
      return sendWhatsAppText(from, "Enter a new 4-6 digit PIN:");
    }
    pinSetSessionsWA[from] = { stage: "verify_old" };
    return sendWhatsAppText(from, "Enter your current PIN to change it:");
  }

  if (lower === "createwallet") {
    for (const chain of SUPPORTED_CHAINS) {
      await ensureChainWallet(user, chain).catch(err => console.warn("ensureChainWallet", chain, err?.message || err));
    }
    const pref = user.preferredChain || SUPPORTED_CHAINS[0];
    const entry = user.wallets.get(pref);
    const msg = entry ? `OK. Wallets created. Preferred (${CHAIN_CONFIG[pref].name}): ${entry.address}` : "OK. Wallets created.";
    return sendWhatsAppText(from, msg);
  }

  if (lower.startsWith("balance")) {
    const parts = raw.split(/\s+/);
    const chain = parts[1] ? parts[1].toLowerCase() : (user.preferredChain || SUPPORTED_CHAINS[0]);
    if (!isValidChain(chain)) return sendWhatsAppText(from, "Unsupported chain.");
    await ensureChainWallet(user, chain);
    const bal = await getChainBalance(user, chain).catch(() => "n/a");
    return sendWhatsAppText(from, `${CHAIN_CONFIG[chain].name}: ${bal} ${CHAIN_CONFIG[chain].symbol}`);
  }

  if (lower.startsWith("address")) {
    const parts = raw.split(/\s+/);
    const chain = parts[1] ? parts[1].toLowerCase() : (user.preferredChain || SUPPORTED_CHAINS[0]);
    if (!isValidChain(chain)) return sendWhatsAppText(from, "Unsupported chain.");
    await ensureChainWallet(user, chain);
    const entry = user.wallets.get(chain);
    return sendWhatsAppText(from, `${CHAIN_CONFIG[chain].name} address: ${entry.address}`);
  }

  if (lower === "send") {
    await sendWhatsAppChainPicker(from);
    return sendWhatsAppText(from, "Or type: send <chain> (polygon/bsc/base/ethereum/ton).");
  }

  if (lower.startsWith("send")) {
    const parts = raw.split(/\s+/);
    const chain = parts[1] ? parts[1].toLowerCase() : (user.preferredChain || SUPPORTED_CHAINS[0]);
    if (!isValidChain(chain)) return sendWhatsAppText(from, "Unsupported chain.");
    sendStateWA[from] = { chain, step: "askRecipient" };
    return sendWhatsAppText(from, `Send (${CHAIN_CONFIG[chain].name}) - enter recipient address:`);
  }

  if (lower.startsWith("ask ")) {
    const q = raw.slice(4).trim();
    if (!q) return sendWhatsAppText(from, "Ask a question after 'ask'.");
    try {
      const reply = await askCenAI(q);
      return sendWhatsAppText(from, reply);
    } catch (e) {
      console.error("WhatsApp AI error", e);
      return sendWhatsAppText(from, "AI error. Try again later.");
    }
  }

  return sendWhatsAppText(from, "Unknown command. Send 'help' for options.");
}

app.get("/whatsapp/webhook", (req, res) => {
  const VERIFY_TOKEN = process.env.WHATSAPP_VERIFY_TOKEN;
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];
  if (mode && token && mode === "subscribe" && token === VERIFY_TOKEN) {
    console.log("WHATSAPP_WEBHOOK_VERIFIED");
    return res.status(200).send(challenge);
  }
  return res.sendStatus(403);
});

app.post("/whatsapp/webhook", async (req, res) => {
  try {
    const body = req.body;
    const changes = body?.entry?.[0]?.changes?.[0];
    const messages = changes?.value?.messages;
    if (!messages || !messages.length) return res.sendStatus(200);
    for (const message of messages) {
      const from = message.from;
      if (message.type === "interactive") {
        const id = message.interactive?.list_reply?.id || message.interactive?.button_reply?.id || null;
        if (id === "wa_send_confirm") { await handleWhatsAppText(from, "confirm"); continue; }
        if (id === "wa_send_cancel") { await handleWhatsAppText(from, "cancel"); continue; }
        const mapped = id ? mapWhatsAppMenuIdToText(id) : null;
        if (mapped) {
          const text = mapped === "ask" ? "ask " : mapped;
          await handleWhatsAppText(from, text);
        } else {
          await sendWhatsAppText(from, "Send a text message. Type `help` for commands.");
        }
        continue;
      }
      if (message.type !== "text") {
        await sendWhatsAppText(from, "Send a text message. Type `help` for commands.");
        continue;
      }
      const text = message.text?.body || "";
      await handleWhatsAppText(from, text);
    }
    res.sendStatus(200);
  } catch (err) {
    console.error("WhatsApp webhook error", err);
    res.sendStatus(500);
  }
});

app.get("/", (req, res) => res.send("CenDeFi Bot running"));
app.listen(WEBHOOK_PORT, () => console.log(`Webhook server listening on port ${WEBHOOK_PORT}`));

console.log("CenDeFi (TON-integrated) bot loaded");

