// server.js
import express from "express";
import fetch from "node-fetch"; // or axios
import dotenv from "dotenv";
import mongoose from "mongoose";
import bodyParser from "body-parser";

dotenv.config();
const app = express();
app.use(bodyParser.json());

// Mongo user model (reuse your existing one)
import User from "./models/user.js"; // your mongoose model

// GET for webhook verification
app.get("/webhook", (req, res) => {
  const VERIFY_TOKEN = process.env.WHATSAPP_VERIFY_TOKEN;
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (mode && token && mode === "subscribe" && token === VERIFY_TOKEN) {
    console.log("WEBHOOK_VERIFIED");
    return res.status(200).send(challenge);
  } else {
    return res.sendStatus(403);
  }
});

// POST for incoming messages (and statuses)
app.post("/webhook", async (req, res) => {
  try {
    const body = req.body;
    // quick sanity check: WhatsApp event structure
    if (body.object && body.entry) {
      const changes = body.entry[0].changes[0];
      const value = changes.value;
      const messages = value.messages;
      if (messages && messages.length) {
        const message = messages[0];
        const from = message.from; // WhatsApp number (string) e.g. "447700900000"
        const text = message.text?.body || "";

        // Map WhatsApp user to your DB user (create if not exists)
        let user = await User.findOne({ whatsappNumber: from });
        if (!user) {
          user = new User({ whatsappNumber: from, createdAt: new Date() });
          await user.save();
        }

        // Simple command parsing (reuse your Telegram handlers)
        if (/^createwallet$/i.test(text.trim())) {
          // call your existing createWallet function that uses User model
          await createWalletForUser(user);
          await sendWhatsAppText(from, `✅ Wallet created! Address: ${user.walletAddress}`);
        } else if (/^balance$/i.test(text.trim())) {
          const bal = await getBalance(user); // implement using ethers/provider
          await sendWhatsAppText(from, `💰 Balance: ${bal} MATIC`);
        } else if (/^ask\s+(.+)/i.test(text.trim())) {
          const q = text.replace(/^ask\s+/i, "");
          const reply = await askNovaAI(user, q); // reuse your OpenAI logic
          await sendWhatsAppText(from, reply);
        } else {
          // fallback help
          await sendWhatsAppText(from, "Commands: createwallet | balance | ask <question>");
        }
      }
    }
    res.sendStatus(200);
  } catch (err) {
    console.error("Webhook error", err);
    res.sendStatus(500);
  }
});

// helper: send message via Graph API
async function sendWhatsAppText(to, message) {
  const phoneId = process.env.WHATSAPP_PHONE_ID;
  const token = process.env.WHATSAPP_TOKEN;
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

app.listen(process.env.PORT || 3000, ()=>console.log("WhatsApp webhook running"));
