/* ============================================================================
   محرك نظام محاسبة الصيدلية الزراعية (يعمل في Electron وفي تطبيق الأندرويد وفي Node للاختبار)
   - كل البيانات = سجل أحداث (event log) لا يُعدَّل. الحالة تُحسب من الأحداث بترتيب ثابت.
   - كل جهاز مستقل ويعمل بدون إنترنت. المزامنة = تبادل الأحداث الناقصة بين الأجهزة (مشفّرة).
   ============================================================================ */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.PharmaEngine = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  /* ------------------------------ أدوات عامة ------------------------------ */
  const DEFAULTS = {
    shop_name: "الصيدلية الزراعية", rate_basis: "sell", auto_rate: "1", rate_interval_min: "30",
    allow_negative_stock: "1", expiry_warn_days: "90", round_syp: "1"
  };
  const SEED_SALT = "7365656453616c7431323334";           // ملح ثابت للرمز الافتراضي حتى يتطابق على كل الأجهزة
  const RC_ALPHA = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const CUR = ["USD", "SYP"];

  class ApiError extends Error { constructor(status, msg) { super(msg); this.status = status; this.error = msg; } }
  const bad = m => new ApiError(400, m);
  const r2 = x => Math.round((+x + 1e-9) * 100) / 100;
  const r3 = x => Math.round((+x + 1e-9) * 1000) / 1000;
  const toUsd = (a, cur, rate) => (cur === "USD" ? a : a / rate);
  const convert = (a, from, to, rate) => (from === to ? a : from === "USD" ? a * rate : a / rate);
  const pad = n => String(n).padStart(2, "0");
  const fmtTs = ms => { const d = new Date(ms); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };

  // أرقام عربية/فارسية/عريضة -> ASCII (سبب مشكلة "الرمز لا يعمل" بلوحات المفاتيح العربية)
  function normDigits(s) {
    return String(s == null ? "" : s).replace(/[٠-٩]/g, c => String(c.charCodeAt(0) - 0x660))
      .replace(/[۰-۹]/g, c => String(c.charCodeAt(0) - 0x6F0))
      .replace(/[０-９]/g, c => String(c.charCodeAt(0) - 0xFF10));
  }
  const normPin = s => normDigits(s).replace(/\s+/g, "");
  const normCode = s => normDigits(s).toUpperCase().replace(/[^A-Z0-9]/g, "");
  const validPin = p => /^[0-9]{4,12}$/.test(p);

  const hasSubtle = () => typeof crypto !== "undefined" && crypto.subtle;
  const te = new TextEncoder(), td = new TextDecoder();
  function toHex(buf) { return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join(""); }
  function fromHex(h) { const a = new Uint8Array(h.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; }
  function b64uEnc(bytes) { let s = ""; const a = new Uint8Array(bytes); for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
  function b64uDec(str) { str = str.replace(/-/g, "+").replace(/_/g, "/"); while (str.length % 4) str += "="; const s = atob(str); const a = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i); return a; }
  const randBytes = n => { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; };
  const randId = n => b64uEnc(randBytes(n));
  const uuid = () => (crypto.randomUUID ? crypto.randomUUID() : toHex(randBytes(16)));
  async function pbkdf2Hex(secret, saltHex, iter = 100000) {
    const key = await crypto.subtle.importKey("raw", te.encode(secret), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: fromHex(saltHex), iterations: iter }, key, 256);
    return toHex(bits);
  }
  async function hashSecret(secret) { const salt = toHex(randBytes(16)); return { salt, hash: await pbkdf2Hex(secret, salt) }; }
  async function checkSecret(secret, rec) { return !!(rec && rec.hash && (await pbkdf2Hex(secret, rec.salt)) === rec.hash); }
  function genRecoveryCode() { const a = randBytes(16); let raw = ""; for (let i = 0; i < 16; i++) raw += RC_ALPHA[a[i] % RC_ALPHA.length]; return raw.match(/.{4}/g).join("-"); }

  /* ------------------------------ سعر الصرف من الليرة اليوم ------------------------------ */
  const NUM = "([0-9][0-9,]*(?:\\.[0-9]+)?)";
  const RATE_PATTERNS = [
    new RegExp("USD\\s+(?:USD\\s*)?US\\s*Dollar\\s+" + NUM + "\\s+" + NUM, "i"),
    new RegExp("US\\s*Dollar\\s+Rate[^0-9]{0,60}Buy\\s+" + NUM + "\\s+[0-9,]+\\s*old\\s+Sell\\s+" + NUM, "i"),
    new RegExp("(?:USD\\s*)?دولار\\s*أمريكي\\s+" + NUM + "\\s+" + NUM, "i"),
    new RegExp("الدولار\\s*الأمريكي[^0-9]{0,40}شراء\\s+" + NUM + "[^0-9]{0,40}مبيع\\s+" + NUM, "i"),
    new RegExp("شراء\\s+" + NUM + "\\s+[0-9,]+\\s*قديم[^0-9]{0,20}مبيع\\s+" + NUM, "i")
  ];
  function parseRateHtml(raw) {
    let t = String(raw).replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " ");
    t = t.replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/\s+/g, " ");
    for (const p of RATE_PATTERNS) {
      const m = t.match(p);
      if (m) {
        let buy = parseFloat(m[1].replace(/,/g, "")), sell = parseFloat(m[2].replace(/,/g, ""));
        if (buy > 2000 || sell > 2000) { buy /= 100; sell /= 100; }      // الليرة القديمة -> الجديدة
        return [buy, sell];
      }
    }
    return null;
  }

  /* ------------------------------ الحالة المشتقة من الأحداث ------------------------------ */
  function newState() {
    return {
      settings: Object.assign({}, DEFAULTS), rates: [], users: new Map(), products: new Map(), customers: new Map(),
      suppliers: new Map(), batches: new Map(), batchesByProduct: new Map(), oversold: new Map(),
      sales: new Map(), salesOrder: [], purchases: new Map(), purchOrder: [], ledger: [], cash: [], expenses: [],
      devCounts: {}, closes: [], periodStart: ""
    };
  }
  const PDEF = { unit: "قطعة", pack_factor: 1, price_mode: "USD", price_usd: 0, price_wholesale_usd: 0, price_syp: 0, price_wholesale_syp: 0, cost_usd: 0, min_stock: 0, active: 1 };
  const PFIELDS = ["code", "barcode", "name", "category", "company", "active_ingredient", "unit", "pack_unit", "pack_factor", "price_mode", "price_usd", "price_wholesale_usd", "price_syp", "price_wholesale_syp", "min_stock", "notes", "active", "packs"];
  const PNUM = new Set(["pack_factor", "price_usd", "price_wholesale_usd", "price_syp", "price_wholesale_syp", "min_stock", "active"]);
  const CFIELDS = ["name", "phone", "village", "type", "credit_limit_usd", "notes", "active"];

  const stockOf = (S, pid) => r3((S.batchesByProduct.get(pid) || []).reduce((a, b) => a + b.qtyRemaining, 0) - (S.oversold.get(pid) || 0));
  const sortedBatches = (S, pid) => (S.batchesByProduct.get(pid) || []).filter(b => b.qtyRemaining > 0).sort((a, b) => (a.expiry ? 0 : 1) - (b.expiry ? 0 : 1) || (a.expiry || "").localeCompare(b.expiry || "") || a.order - b.order);

  function allocFefo(S, pid, qtyBase) {
    const p = S.products.get(pid), out = []; let left = qtyBase;
    for (const b of sortedBatches(S, pid)) {
      if (left <= 1e-9) break;
      const take = Math.min(left, b.qtyRemaining);
      out.push([b.id, take, b.costUsd || (p && p.cost_usd) || 0]); left -= take;
    }
    if (left > 1e-9) out.push([null, left, (p && p.cost_usd) || 0]);
    return out;
  }

  function upsertEntity(map, d, fields, defaults, t, numeric) {
    const cur = map.get(d.id) || Object.assign({ id: d.id, createdT: t }, defaults);
    for (const k of fields) if (k in d) cur[k] = d[k];
    map.set(d.id, cur);
  }

  function saleCreate(S, e, counts) {
    const d = e.d, rows = []; let cost = 0;
    for (const it of d.items) {
      const allocs = allocFefo(S, it.productId, it.base); let given = 0;
      allocs.forEach(([bid, q, c], i) => {
        const frac = q / it.base, lt = i === allocs.length - 1 ? r2(it.line - given) : r2(it.line * frac); given += lt;
        rows.push({ productId: it.productId, batchId: bid, unit: it.unit, qtyUnit: r3(it.qty * frac), qtyBase: r3(q), price: it.price, lineTotal: lt, costUsd: r2(c * q) });
        cost += c * q;
        if (bid) { const b = S.batches.get(bid); b.qtyRemaining = r3(b.qtyRemaining - q); }
        else S.oversold.set(it.productId, r3((S.oversold.get(it.productId) || 0) + q));
      });
    }
    S.sales.set(d.id, { id: d.id, number: d.number, ts: d.ts, customerId: d.customerId, userId: e.by, currency: d.currency, rate: d.rate, subtotal: d.subtotal, discount: d.discount, total: d.total, paid: d.paid, totalUsd: d.totalUsd, costUsd: r2(cost), note: d.note, voided: 0, items: rows, t: e.t });
    S.salesOrder.push(d.id);
    if (counts) { const dc = S.devCounts[e.dev] || (S.devCounts[e.dev] = { sale: 0 }); dc.sale++; }
    const rem = r2(d.total - d.paid);
    if (rem > 0.005) S.ledger.push({ ts: d.ts, party_type: "customer", party_id: d.customerId, currency: d.currency, amount: rem, kind: "sale", ref_id: d.id, note: "فاتورة " + d.number, voided: 0 });
    if (d.paid > 0.005) S.cash.push({ ts: d.ts, currency: d.currency, amount: r2(d.paid), kind: "sale", ref_id: d.id, note: "فاتورة " + d.number, voided: 0 });
  }
  function saleVoid(S, id) {
    const s = S.sales.get(id); if (!s || s.voided || s.archived) return;
    for (const it of s.items) {
      if (it.batchId) { const b = S.batches.get(it.batchId); if (b) b.qtyRemaining = r3(b.qtyRemaining + it.qtyBase); }
      else S.oversold.set(it.productId, Math.max(0, r3((S.oversold.get(it.productId) || 0) - it.qtyBase)));
    }
    s.voided = 1;
    for (const x of S.ledger) if (x.ref_id === s.id && x.kind === "sale") x.voided = 1;
    for (const x of S.cash) if (x.ref_id === s.id && x.kind === "sale") x.voided = 1;
  }
  const partyBal = (S, type, id) => { const b = { USD: 0, SYP: 0 }; for (const x of S.ledger) if (!x.voided && x.party_type === type && x.party_id === id) b[x.currency] += x.amount; return { USD: r2(b.USD), SYP: r2(b.SYP) }; };
  const lastRate = S => { const r = S.rates[S.rates.length - 1]; return r ? (S.settings.rate_basis === "sell" ? r.sell : r.buy) : 0; };
  /* تجميع شغل فترة (closeId = null -> السنة الحالية غير المقفلة) */
  function periodData(S, closeId) {
    const inP = x => !x.voided && (closeId ? x.closeId === closeId : !x.archived);
    const sales = [...S.sales.values()].filter(inP), purchases = [...S.purchases.values()].filter(inP), expenses = S.expenses.filter(x => closeId ? x.closeId === closeId : !x.archived);
    let rev = 0, cost = 0, purUsd = 0, expUsd = 0; const byCur = {}, months = new Map(), top = new Map();
    for (const s of sales) {
      rev += s.totalUsd; cost += s.costUsd; const c = byCur[s.currency] || (byCur[s.currency] = { total: 0, paid: 0 }); c.total = r2(c.total + s.total); c.paid = r2(c.paid + s.paid);
      const mk = s.ts.slice(0, 7), m = months.get(mk) || { month: mk, n: 0, rev_usd: 0, profit_usd: 0 }; m.n++; m.rev_usd += s.totalUsd; m.profit_usd += s.totalUsd - s.costUsd; months.set(mk, m);
      for (const it of s.items) { const pr = S.products.get(it.productId) || {}, g = top.get(it.productId) || { name: pr.name, unit: pr.unit, qty: 0, rev_usd: 0, cost_usd: 0 }; g.qty += it.qtyBase; g.rev_usd += toUsd(it.lineTotal, s.currency, s.rate); g.cost_usd += it.costUsd; top.set(it.productId, g); }
    }
    for (const p of purchases) purUsd += p.totalUsd; for (const e of expenses) expUsd += e.amount_usd;
    return {
      sales, purchases, expenses,
      summary: { invoices: sales.length, revenue_usd: r2(rev), cost_usd: r2(cost), profit_usd: r2(rev - cost), expenses_usd: r2(expUsd), net_usd: r2(rev - cost - expUsd), purchases_usd: r2(purUsd), sales_by_currency: byCur },
      months: [...months.values()].sort((a, b) => a.month.localeCompare(b.month)).map(m => ({ month: m.month, n: m.n, rev_usd: r2(m.rev_usd), profit_usd: r2(m.profit_usd) })),
      top: [...top.values()].sort((a, b) => b.rev_usd - a.rev_usd).slice(0, 15).map(g => ({ name: g.name, unit: g.unit, qty: r3(g.qty), rev_usd: r2(g.rev_usd), profit_usd: r2(g.rev_usd - g.cost_usd) }))
    };
  }
  function debtSnapshot(S) {
    const rate = lastRate(S) || 1, out = { customers: [], suppliers: [] };
    for (const [type, map, key] of [["customer", S.customers, "customers"], ["supplier", S.suppliers, "suppliers"]]) for (const p of map.values()) {
      const b = partyBal(S, type, p.id); if (Math.abs(b.USD) > 0.004 || Math.abs(b.SYP) > 0.004) out[key].push({ id: p.id, name: p.name, phone: p.phone || null, USD: b.USD, SYP: b.SYP, total_usd: r2(b.USD + b.SYP / rate) });
    }
    for (const k of ["customers", "suppliers"]) out[k].sort((a, b) => b.total_usd - a.total_usd); return out;
  }
  function stockSnapshot(S) {
    const rows = []; let value = 0;
    for (const p of S.products.values()) {
      if (!p.active) continue; const bs = (S.batchesByProduct.get(p.id) || []).filter(b => b.qtyRemaining > 0), st = stockOf(S, p.id), v = bs.reduce((a, b) => a + b.qtyRemaining * b.costUsd, 0); value += v;
      if (st > 0) rows.push({ name: p.name, unit: p.unit, stock: st, value_usd: r2(v), batches: bs.map(b => ({ batch_no: b.batchNo, expiry: b.expiry, qty: b.qtyRemaining })) });
    }
    rows.sort((a, b) => a.name.localeCompare(b.name, "ar")); return { value_usd: r2(value), rows };
  }
  function cashSnapshot(S) { const b = {}; for (const c of S.cash) if (!c.voided) b[c.currency] = (b[c.currency] || 0) + c.amount; for (const k of Object.keys(b)) b[k] = r2(b[k]); return b; }
  /* إقفال السنة: أرشفة الفواتير والمصاريف + ترحيل الأرصدة (ديون/مستحقات/صندوق) كرصيد افتتاحي. المخزون والأصناف والزبائن تبقى */
  function yearClose(S, e) {
    const d = e.d, pd = periodData(S, null);
    const cl = { id: d.id, ts: d.ts, label: d.label, summary: pd.summary, months: pd.months, top: pd.top, debts: debtSnapshot(S), stock: stockSnapshot(S), cash: cashSnapshot(S), from: S.periodStart || null };
    for (const x of S.sales.values()) if (!x.archived) { x.archived = 1; x.closeId = d.id; }
    for (const x of S.purchases.values()) if (!x.archived) { x.archived = 1; x.closeId = d.id; }
    for (const x of S.expenses) if (!x.archived) { x.archived = 1; x.closeId = d.id; }
    const bal = new Map(); for (const x of S.ledger) if (!x.voided) { const k = x.party_type + "|" + x.party_id + "|" + x.currency; bal.set(k, (bal.get(k) || 0) + x.amount); }
    S.ledger = []; for (const [k, v] of bal) { const [pt, pid, cur] = k.split("|"); if (Math.abs(v) > 0.004) S.ledger.push({ ts: d.ts, party_type: pt, party_id: pid, currency: cur, amount: r2(v), kind: "carry", ref_id: d.id, note: "رصيد مرحّل من " + d.label, voided: 0 }); }
    const cb = {}; for (const c of S.cash) if (!c.voided) cb[c.currency] = (cb[c.currency] || 0) + c.amount;
    S.cash = []; for (const k of Object.keys(cb)) if (Math.abs(cb[k]) > 0.004) S.cash.push({ ts: d.ts, currency: k, amount: r2(cb[k]), kind: "carry", ref_id: d.id, note: "رصيد مرحّل من " + d.label, voided: 0 });
    S.closes.push(cl); S.periodStart = d.ts;
  }

  const APPLY = {
    "settings.set"(S, e) { for (const k of Object.keys(e.d.values || {})) if (k in DEFAULTS) S.settings[k] = String(e.d.values[k]); },
    "rate.set"(S, e) { S.rates.push({ id: S.rates.length + 1, ts: e.d.ts, buy: e.d.buy, sell: e.d.sell, source: e.d.source }); },
    "user.upsert"(S, e) {
      const d = e.d, cur = S.users.get(d.id) || { id: d.id, name: "", role: "cashier", active: 1, mustChange: 0, pin: null, recovery: null, createdT: e.t };
      for (const k of ["name", "role", "active", "mustChange", "pin", "recovery"]) if (k in d) cur[k] = d[k];
      S.users.set(d.id, cur);
    },
    "product.upsert"(S, e) { upsertEntity(S.products, e.d, PFIELDS, PDEF, e.t); },
    "product.delete"(S, e) { const p = S.products.get(e.d.id); if (p) p.active = 0; },
    "customer.upsert"(S, e) { upsertEntity(S.customers, e.d, CFIELDS, { type: "farmer", credit_limit_usd: 0, active: 1 }, e.t); },
    "customer.delete"(S, e) { const p = S.customers.get(e.d.id); if (p) p.active = 0; },
    "supplier.upsert"(S, e) { upsertEntity(S.suppliers, e.d, ["name", "phone", "notes", "active"], { active: 1 }, e.t); },
    "supplier.delete"(S, e) { const p = S.suppliers.get(e.d.id); if (p) p.active = 0; },
    "prices.bulk"(S, e) {
      const k = 1 + (+e.d.percent || 0) / 100;
      for (const p of S.products.values()) if (p.active && p.price_mode === "USD") { p.price_usd = r2(p.price_usd * k); p.price_wholesale_usd = r2(p.price_wholesale_usd * k); }
    },
    "purchase.create"(S, e) {
      const d = e.d;
      for (const it of d.items) {
        const b = { id: it.batchId, productId: it.productId, batchNo: it.batchNo || null, expiry: it.expiry || null, qtyIn: it.base, qtyRemaining: it.base, costUsd: it.costBaseUsd, purchaseId: d.id, created: d.ts, order: S.batches.size };
        const ov = S.oversold.get(it.productId) || 0;             // بضاعة بيعت قبل إدخالها
        if (ov > 0) { const ab = Math.min(ov, b.qtyRemaining); b.qtyRemaining = r3(b.qtyRemaining - ab); S.oversold.set(it.productId, r3(ov - ab)); }
        S.batches.set(b.id, b);
        if (!S.batchesByProduct.has(b.productId)) S.batchesByProduct.set(b.productId, []);
        S.batchesByProduct.get(b.productId).push(b);
        const p = S.products.get(it.productId); if (p) p.cost_usd = it.costBaseUsd;
      }
      S.purchases.set(d.id, Object.assign({ userId: e.by, t: e.t, voided: 0 }, d)); S.purchOrder.push(d.id);
      const rem = r2(d.total - d.paid);
      if (rem > 0.005) S.ledger.push({ ts: d.ts, party_type: "supplier", party_id: d.supplierId, currency: d.currency, amount: rem, kind: "purchase", ref_id: d.id, note: "شراء " + (d.invoiceNo || ""), voided: 0 });
      if (d.paid > 0.005) S.cash.push({ ts: d.ts, currency: d.currency, amount: -r2(d.paid), kind: "purchase", ref_id: d.id, note: "شراء", voided: 0 });
    },
    "sale.create"(S, e) { saleCreate(S, e, true); },
    "sale.edit"(S, e) { saleVoid(S, e.d.replaces); saleCreate(S, e, false); const ns = S.sales.get(e.d.id); if (ns) ns.editedFrom = e.d.replaces; },
    "sale.void"(S, e) { saleVoid(S, e.d.id); },
    "stock.addbatch"(S, e) {
      const d = e.d, b = { id: d.batchId, productId: d.productId, batchNo: d.batchNo || null, expiry: d.expiry || null, qtyIn: d.qty, qtyRemaining: d.qty, costUsd: d.cost || 0, purchaseId: null, created: d.ts, order: S.batches.size };
      const ov = S.oversold.get(d.productId) || 0; if (ov > 0) { const ab = Math.min(ov, b.qtyRemaining); b.qtyRemaining = r3(b.qtyRemaining - ab); S.oversold.set(d.productId, r3(ov - ab)); }
      S.batches.set(b.id, b); if (!S.batchesByProduct.has(d.productId)) S.batchesByProduct.set(d.productId, []); S.batchesByProduct.get(d.productId).push(b);
    },
    "year.close"(S, e) { yearClose(S, e); },
    "payment.create"(S, e) {
      const d = e.d;
      S.ledger.push({ ts: d.ts, party_type: d.partyType, party_id: d.partyId, currency: d.applyCur, amount: -d.applied, kind: "payment", ref_id: d.id, note: d.note, orig_currency: d.payCur, orig_amount: d.amount, rate: d.rate, voided: 0 });
      S.cash.push({ ts: d.ts, currency: d.payCur, amount: d.partyType === "customer" ? d.amount : -d.amount, kind: d.partyType + "_payment", ref_id: d.id, note: d.partyName + (d.note ? " - " + d.note : ""), voided: 0 });
    },
    "expense.create"(S, e) {
      const d = e.d;
      S.expenses.push({ id: d.id, ts: d.ts, category: d.category, amount: d.amount, currency: d.currency, rate: d.rate, amount_usd: d.amountUsd, note: d.note });
      S.cash.push({ ts: d.ts, currency: d.currency, amount: -d.amount, kind: "expense", ref_id: d.id, note: d.category, voided: 0 });
    },
    "stock.adjust"(S, e) {
      const d = e.d, pid = d.productId;
      if (d.batchId) { const b = S.batches.get(d.batchId); if (b) b.qtyRemaining = r3(d.newQty); return; }
      S.oversold.set(pid, 0);
      const cur = (S.batchesByProduct.get(pid) || []).reduce((a, b) => a + b.qtyRemaining, 0), delta = d.newQty - cur;
      if (delta > 1e-9) {
        const b = { id: d.newBatchId, productId: pid, batchNo: "جرد", expiry: d.expiry || null, qtyIn: r3(delta), qtyRemaining: r3(delta), costUsd: d.cost || 0, purchaseId: null, created: d.ts, order: S.batches.size };
        S.batches.set(b.id, b); if (!S.batchesByProduct.has(pid)) S.batchesByProduct.set(pid, []); S.batchesByProduct.get(pid).push(b);
      } else if (delta < -1e-9) {
        let left = -delta;
        for (const b of sortedBatches(S, pid)) { if (left <= 1e-9) break; const take = Math.min(left, b.qtyRemaining); b.qtyRemaining = r3(b.qtyRemaining - take); left -= take; }
      }
    }
  };

  const cmpEv = (a, b) => a.t - b.t || (a.dev < b.dev ? -1 : a.dev > b.dev ? 1 : 0) || a.seq - b.seq;

  /* ------------------------------ المخزن في الذاكرة (للاختبار) ------------------------------ */
  class MemoryStore {
    constructor() { this.ev = new Map(); this.meta = new Map(); }
    async init() { }
    async loadEvents() { return [...this.ev.values()]; }
    async putEvents(list) { for (const e of list) this.ev.set(e.id, e); }
    async getMeta(k) { return this.meta.has(k) ? JSON.parse(this.meta.get(k)) : null; }
    async setMeta(k, v) { this.meta.set(k, JSON.stringify(v)); }
    async clearAll() { this.ev.clear(); this.meta.clear(); }
  }

  /* ============================== المحرك ============================== */
  class Engine {
    constructor(opts) {
      this.store = opts.store; this.clock = opts.clock || { now: () => Date.now() };
      this.fetchText = opts.fetchText || (async u => (await fetch(u)).text());
      this.getHosts = opts.getHosts || (async () => []);
      this.seed = opts.seed || (typeof PHARMA_SEED !== "undefined" ? PHARMA_SEED : []);
      this.pbkdfIter = opts.pbkdfIter || 100000;
      this.listeners = {}; this.cur = null; this.q = Promise.resolve(); this.fails = { n: 0, until: 0 }; this.autoTimer = null;
      this.syncing = false; this.syncState = {};
    }
    on(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); }
    emit(ev, a) { (this.listeners[ev] || []).forEach(f => { try { f(a); } catch (e) { console.error(e); } }); }
    _lock(fn) { const p = this.q.then(() => fn()); this.q = p.catch(() => { }); return p; }
    now() { return this.clock.now(); }
    today() { return fmtTs(this.now()).slice(0, 10); }
    ts() { return fmtTs(this.now()); }

    async init() {
      let meta = await this.store.getMeta("meta");
      if (!meta) {
        meta = { deviceId: uuid(), group: { gid: randId(16), secret: randId(32), name: "" }, remotes: [], relayUrl: "", lastSyncAt: null, created: this.now() };
        await this.store.setMeta("meta", meta);
      }
      this.meta = meta; this.devCode = meta.deviceId.replace(/[^a-z0-9]/gi, "").slice(0, 4).toUpperCase();
      this.byDev = {}; this.vec = {}; this.sorted = []; this.maxT = 0;
      const evs = await this.store.loadEvents();
      this._addMany(evs, true);
      if (!evs.length) await this._seed();

    }

    async _seed() {
      const evs = []; let seq = 0;
      const mk = (type, d) => { seq++; evs.push({ id: "seed:" + seq, dev: "seed", seq, t: seq, type, by: "seed", d }); };
      mk("user.upsert", { id: "owner", name: "المدير", role: "owner", active: 1, mustChange: 1, pin: { salt: SEED_SALT, hash: await pbkdf2Hex("1234", SEED_SALT) } });
      this.seed.forEach((p, i) => mk("product.upsert", { id: "p" + (i + 1), category: p[0], name: p[1], active_ingredient: p[2], unit: p[3], pack_unit: p[4] || null, pack_factor: p[5] || 1 }));
      const added = this._addMany(evs); await this.store.putEvents(added);
    }

    /* ---- إدخال الأحداث ---- */
    _addMany(evs, noMaxCheck) {
      evs = evs.slice().sort((a, b) => (a.dev < b.dev ? -1 : a.dev > b.dev ? 1 : 0) || a.seq - b.seq);
      const added = [];
      for (const ev of evs) {
        const arr = this.byDev[ev.dev] || (this.byDev[ev.dev] = []);
        if (ev.seq <= arr.length || ev.seq !== arr.length + 1) continue;     // مكرر أو فيه فجوة (سيصل لاحقاً)
        arr.push(ev); this.vec[ev.dev] = ev.seq; if (ev.t > this.maxT) this.maxT = ev.t; added.push(ev);
      }
      if (!added.length) return [];
      added.sort(cmpEv);
      const last = this.sorted[this.sorted.length - 1];
      if (!this.S || !last || cmpEv(added[0], last) > 0) {
        if (!this.S) this.S = newState();
        for (const ev of added) { this.sorted.push(ev); this._apply(ev); }
      } else { this.sorted = this.sorted.concat(added).sort(cmpEv); this._rebuild(); }
      return added;
    }
    _rebuild() { this.S = newState(); for (const ev of this.sorted) this._apply(ev); }
    _apply(ev) { const f = APPLY[ev.type]; if (f) { try { f(this.S, ev); } catch (e) { console.error("apply failed", ev.type, e); } } }
    async _commit(type, d) {
      const dev = this.meta.deviceId, seq = (this.vec[dev] || 0) + 1, t = Math.max(this.now(), this.maxT + 1);
      const ev = { id: dev + ":" + seq, dev, seq, t, type, by: this.cur ? this.cur.id : null, d };
      await this.store.putEvents([ev]);
      this._addMany([ev]); this.emit("change", { local: true });
      return ev;
    }

    /* ---- الواجهة البرمجية (نفس مسارات الـ REST القديمة ليبقى شكل الواجهة كما هو) ---- */
    api(method, path, body, query) {
      if (String(path).replace(/^\/+|\/+$/g, "") === "sync/now" && method === "POST") { this._auth(); return this.syncNow(); }
      return this._lock(async () => {
        try { return await this._route(method, path, body || {}, query || {}); }
        catch (e) { if (e instanceof ApiError) throw e; console.error(e); throw new ApiError(500, "خطأ داخلي: " + (e && e.message)); }
      });
    }
    _auth() { if (!this.cur) throw new ApiError(401, "يلزم تسجيل الدخول"); return this.S.users.get(this.cur.id) || this.cur; }
    _owner() { const u = this._auth(); if (u.role !== "owner") throw new ApiError(403, "هذه العملية للمدير فقط"); return u; }
    _rate() {
      const r = this.S.rates[this.S.rates.length - 1]; if (!r) return null;
      const use = this.S.settings.rate_basis === "sell" ? r.sell : r.buy;
      return { id: r.id, ts: r.ts, buy: r.buy, sell: r.sell, use, source: r.source, basis: this.S.settings.rate_basis, old_equiv: r2(use * 100) };
    }
    _needRate() { const r = this._rate(); if (!r) throw bad("لا يوجد سعر صرف. أدخل السعر من الإعدادات أو حدّثه من الليرة اليوم."); return r; }
    _userView(u) { return { id: u.id, name: u.name, role: u.role, must_change: u.mustChange ? 1 : 0, has_recovery: !!u.recovery }; }
    _bal(type, id) { const b = { USD: 0, SYP: 0 }; for (const x of this.S.ledger) if (!x.voided && x.party_type === type && x.party_id === id) b[x.currency] += x.amount; return { USD: r2(b.USD), SYP: r2(b.SYP) }; }
    _debtUsd(cid, rate) { const b = this._bal("customer", cid); return b.USD + b.SYP / rate; }
    _pubProduct(p, owner) {
      const o = Object.assign({}, p), bs = (this.S.batchesByProduct.get(p.id) || []).filter(b => b.qtyRemaining > 0 && b.expiry);
      o.stock = stockOf(this.S, p.id); o.next_expiry = bs.length ? bs.map(b => b.expiry).sort()[0] : null;
      delete o.createdT; if (!owner) delete o.cost_usd; return o;
    }

    async _route(method, path, body, query) {
      const qi = path.indexOf("?");
      if (qi >= 0) { const sp = new URLSearchParams(path.slice(qi + 1)); sp.forEach((v, k) => { query[k] = v; }); path = path.slice(0, qi); }
      path = path.replace(/^\/+|\/+$/g, "");
      const parts = path.split("/"), head = parts[0], S = this.S;

      /* --- بدون تسجيل دخول --- */
      if (path === "ping") return { ok: true };
      if (path === "public/users") return { shop: S.settings.shop_name, users: [...S.users.values()].filter(u => u.active).sort((a, b) => a.createdT - b.createdT).map(u => ({ id: u.id, name: u.name })) };
      if (path === "login" && method === "POST") return this._login(body);
      if (path === "recover" && method === "POST") return this._recover(body);
      if (path === "device/reset" && method === "POST") return this._factoryReset(body);
      if (path === "sync/pairing-peek" && method === "POST") return this._peekPairing(body);

      const user = this._auth();
      if (path === "me") return this._userView(user);
      if (path === "logout" && method === "POST") { this.cur = null; return { ok: true }; }
      if (path === "me/pin" && method === "POST") {
        const np = normPin(body.new_pin); if (!validPin(np)) throw bad("الرمز يجب أن يكون أرقاماً (4 إلى 12)");
        if (!(await checkSecret(normPin(body.old_pin), user.pin))) throw new ApiError(403, "الرمز الحالي غير صحيح");
        await this._commit("user.upsert", { id: user.id, pin: await this._hash(np), mustChange: 0 }); return { ok: true };
      }
      if (path === "me/recovery" && method === "POST") {
        this._owner();
        if (!(await checkSecret(normPin(body.pin), user.pin))) throw new ApiError(403, "الرمز غير صحيح");
        const code = genRecoveryCode(); await this._commit("user.upsert", { id: user.id, recovery: await this._hash(normCode(code)) });
        return { recovery_code: code };
      }

      /* --- الإعدادات وسعر الصرف --- */
      if (path === "settings") {
        if (method === "GET") return Object.assign({}, S.settings);
        this._owner(); const v = {}; for (const k of Object.keys(body)) if (k in DEFAULTS) v[k] = String(body[k]);
        await this._commit("settings.set", { values: v }); return Object.assign({}, this.S.settings);
      }
      if (path === "rate") {
        if (method === "GET") return this._rate() || {};
        this._owner(); return this._setRate(+(body.buy || body.sell), +(body.sell || body.buy), "manual");
      }
      if (path === "rate/refresh" && method === "POST") return this._refreshRate(true);
      if (path === "rate/history") return S.rates.slice(-60).reverse();

      /* --- الأصناف --- */
      if (head === "products") {
        const owner = user.role === "owner";
        if (parts.length === 1 && method === "GET") return [...S.products.values()].filter(p => p.active).sort((a, b) => a.name.localeCompare(b.name, "ar")).map(p => this._pubProduct(p, owner));
        if (parts.length === 1 && method === "POST") { this._owner(); const id = uuid(); await this._commit("product.upsert", Object.assign({ id }, this._cleanProduct(body, true))); return { id }; }
        if (parts.length === 2 && parts[1] === "bulk_prices" && method === "POST") { this._owner(); const pct = +body.percent || 0; await this._commit("prices.bulk", { percent: pct }); return { ok: true }; }
        if (parts.length === 2 && method === "PUT") { this._owner(); if (!S.products.has(parts[1])) throw new ApiError(404, "الصنف غير موجود"); await this._commit("product.upsert", Object.assign({ id: parts[1] }, this._cleanProduct(body, false))); return { ok: true }; }
        if (parts.length === 2 && method === "DELETE") { this._owner(); await this._commit("product.delete", { id: parts[1] }); return { ok: true }; }
        if (parts.length === 3 && parts[2] === "batches") return (S.batchesByProduct.get(parts[1]) || []).slice().sort((a, b) => (a.expiry ? 0 : 1) - (b.expiry ? 0 : 1) || (a.expiry || "").localeCompare(b.expiry || "") || a.order - b.order)
          .map(b => ({ id: b.id, product_id: b.productId, batch_no: b.batchNo, expiry: b.expiry, qty_in: b.qtyIn, qty_remaining: b.qtyRemaining, cost_usd: b.costUsd }));
      }
      if (path === "stock/adjust" && method === "POST") {
        this._owner(); const p = S.products.get(body.product_id); if (!p) throw bad("الصنف غير موجود");
        const nq = +body.new_qty; if (!(nq >= 0)) throw bad("الكمية لا يمكن أن تكون سالبة");
        if (body.batch_id && !S.batches.has(body.batch_id)) throw bad("الدفعة غير موجودة");
        const delta = body.batch_id ? nq - S.batches.get(body.batch_id).qtyRemaining : nq - stockOf(S, p.id);
        await this._commit("stock.adjust", { id: uuid(), productId: p.id, newQty: nq, batchId: body.batch_id || null, newBatchId: uuid(), reason: body.reason || "جرد", ts: this.ts(), cost: p.cost_usd }); return { ok: true, delta: r3(delta) };
      }

      /* --- الزبائن والموردون --- */
      if (head === "customers" || head === "suppliers") return this._parties(head, parts, method, body, user);
      if (path === "payments" && method === "POST") return this._payment(body, user);

      /* --- المبيعات --- */
      if (head === "sales") {
        if (parts.length === 1 && method === "POST") return this._createSale(body);
        if (parts.length === 1 && method === "GET") return this._salesList(query);
        if (parts.length === 2 && method === "GET") return this._saleDetail(parts[1]);
        if (parts.length === 3 && parts[2] === "void" && method === "POST") {
          this._owner(); const s = S.sales.get(parts[1]); if (!s) throw new ApiError(404, "الفاتورة غير موجودة"); if (s.voided) throw bad("الفاتورة محذوفة مسبقاً");
          if (s.archived) throw bad("هذه الفاتورة من سنة مقفلة ولا يمكن حذفها");
          await this._commit("sale.void", { id: s.id }); return { ok: true };
        }
        if (parts.length === 3 && parts[2] === "edit" && method === "POST") {
          this._owner(); const s = S.sales.get(parts[1]); if (!s || s.voided) throw new ApiError(404, "الفاتورة غير موجودة");
          if (s.archived) throw bad("هذه الفاتورة من سنة مقفلة ولا يمكن تعديلها");
          return this._createSale(body, s);
        }
      }
      /* --- المشتريات والمصاريف --- */
      if (head === "purchases") {
        this._owner();
        if (parts.length === 1 && method === "POST") return this._createPurchase(body);
        if (parts.length === 1 && method === "GET") return S.purchOrder.slice().reverse().filter(id => !S.purchases.get(id).archived).slice(0, 200).map(id => this._purchView(S.purchases.get(id)));
        if (parts.length === 2 && method === "GET") { const p = S.purchases.get(parts[1]); if (!p) throw new ApiError(404, "غير موجود"); return Object.assign(this._purchView(p), { items: p.items.map(i => ({ name: (S.products.get(i.productId) || {}).name, unit: i.unit, qty_unit: i.qty, cost: i.cost, batch_no: i.batchNo, expiry: i.expiry })) }); }
      }
      if (head === "expenses") {
        if (parts.length === 1 && method === "POST") {
          this._owner(); const cur = body.currency || "SYP", amt = +body.amount || 0; if (amt <= 0 || !CUR.includes(cur)) throw bad("مبلغ/عملة غير صحيحة");
          const rate = this._needRate().use, id = uuid();
          await this._commit("expense.create", { id, ts: this.ts(), category: body.category || "عام", amount: amt, currency: cur, rate, amountUsd: r2(toUsd(amt, cur, rate)), note: body.note || "" }); return { id };
        }
        if (parts.length === 1 && method === "GET") {
          this._owner(); const [f, t] = this._range(query, true);
          return S.expenses.filter(e => !e.archived && e.ts >= f && e.ts <= t).slice().reverse().slice(0, 500);
        }
      }

      /* --- المخزون والجرد --- */
      if (path === "inventory" && method === "GET") { this._owner(); return this._inventory(); }
      if (path === "stock/count" && method === "POST") { this._owner(); return this._stockCount(body); }
      if (path === "stock/add_batch" && method === "POST") {
        this._owner(); const p = S.products.get(body.product_id); if (!p) throw bad("الصنف غير موجود");
        const qty = +body.qty || 0; if (qty <= 0) throw bad("الكمية غير صحيحة");
        let ex = (body.expiry || "").trim() || null; if (ex && !/^\d{4}-\d{2}(-\d{2})?$/.test(ex)) throw bad("صيغة التاريخ: YYYY-MM-DD"); if (ex && ex.length === 7) ex += "-28";
        await this._commit("stock.addbatch", { batchId: uuid(), productId: p.id, qty: r3(qty), expiry: ex, batchNo: (body.batch_no || "").trim() || "جرد", cost: p.cost_usd || 0, ts: this.ts() }); return { ok: true };
      }
      /* --- إقفال السنة --- */
      if (head === "year") {
        this._owner();
        if (path === "year/closes") return S.closes.slice().reverse().map(c => ({ id: c.id, label: c.label, ts: c.ts, summary: c.summary }));
        if (path === "year/report") return this._yearReport(query.close || null);
        if (path === "year/close" && method === "POST") {
          const label = String(body.label || "").trim(); if (!label) throw bad("اكتب اسم السنة (مثال 2026)");
          if (!(await checkSecret(normPin(body.pin), user.pin))) throw new ApiError(403, "الرمز غير صحيح");
          const id = uuid(); await this._commit("year.close", { id, ts: this.ts(), label }); return { ok: true, id };
        }
      }
      /* --- التقارير --- */
      if (path === "dashboard") return this._dashboard(user);
      if (head === "reports") {
        this._owner();
        if (path === "reports/summary") return this._reportSummary(query);
        if (path === "reports/stock") return this._reportStock(query);
        if (path === "reports/debts/customers") return this._reportDebts("customer");
        if (path === "reports/debts/suppliers") return this._reportDebts("supplier");
      }

      /* --- المستخدمون والنسخ الاحتياطي --- */
      if (head === "users") { this._owner(); return this._users(parts, method, body, user); }
      if (path === "backup" && method === "GET") { this._owner(); return { format: "agri-backup-v1", exportedAt: this.ts(), device: this.meta.deviceId, events: this.sorted.slice() }; }
      if (path === "backup/restore" && method === "POST") {
        this._owner(); if (!body || body.format !== "agri-backup-v1" || !Array.isArray(body.events)) throw bad("ملف النسخة الاحتياطية غير صالح");
        const n = await this._ingest(body.events); return { ok: true, added: n };
      }
      if (head === "sync" || path === "info") return this._syncRoute(path, parts, method, body, user);
      throw new ApiError(404, "مسار غير معروف");
    }

    _inventory() {
      const S = this.S, todayMs = new Date(this.today() + "T00:00:00").getTime(), rows = [];
      for (const p of [...S.products.values()].filter(p => p.active).sort((a, b) => a.name.localeCompare(b.name, "ar"))) {
        const bs = (S.batchesByProduct.get(p.id) || []).filter(b => b.qtyRemaining > 0).sort((a, b) => (a.expiry ? 0 : 1) - (b.expiry ? 0 : 1) || (a.expiry || "").localeCompare(b.expiry || "") || a.order - b.order);
        rows.push({ id: p.id, name: p.name, category: p.category, unit: p.unit, pack_unit: p.pack_unit, pack_factor: p.pack_factor, min_stock: p.min_stock, stock: stockOf(S, p.id), oversold: S.oversold.get(p.id) || 0,
          batches: bs.map(b => ({ id: b.id, batch_no: b.batchNo, expiry: b.expiry, qty: b.qtyRemaining, cost_usd: b.costUsd, days_left: b.expiry ? Math.floor((new Date(b.expiry + "T00:00:00").getTime() - todayMs) / 86400000) : null })) });
      }
      return { warn_days: +S.settings.expiry_warn_days || 90, rows };
    }
    async _stockCount(body) {
      const S = this.S, rows = Array.isArray(body.rows) ? body.rows : [], diffs = [];
      for (const r of rows) {
        const p = S.products.get(r.product_id); if (!p) continue; const nq = +r.new_qty; if (!(nq >= 0)) throw bad("كمية غير صحيحة للصنف «" + p.name + "»");
        if (r.batch_id) { const b = S.batches.get(r.batch_id); if (!b || Math.abs(b.qtyRemaining - nq) < 1e-9) continue; diffs.push({ name: p.name, unit: p.unit, batch_no: b.batchNo, expiry: b.expiry, before: b.qtyRemaining, after: nq }); await this._commit("stock.adjust", { id: uuid(), productId: p.id, newQty: nq, batchId: b.id, newBatchId: uuid(), reason: "جرد", ts: this.ts(), cost: p.cost_usd }); }
        else { const cur = stockOf(S, p.id); if (Math.abs(cur - nq) < 1e-9) continue; diffs.push({ name: p.name, unit: p.unit, batch_no: null, expiry: null, before: cur, after: nq }); await this._commit("stock.adjust", { id: uuid(), productId: p.id, newQty: nq, batchId: null, newBatchId: uuid(), reason: "جرد", ts: this.ts(), cost: p.cost_usd }); }
      }
      return { ok: true, changed: diffs.length, diffs };
    }
    _yearReport(closeId) {
      const S = this.S, cl = closeId ? S.closes.find(c => c.id === closeId) : null; if (closeId && !cl) throw new ApiError(404, "السنة غير موجودة");
      const pd = periodData(S, closeId || null), tsOf = x => x.ts, all = pd.sales.map(tsOf).concat(pd.purchases.map(tsOf), pd.expenses.map(tsOf)).sort();
      const cname = id => (S.customers.get(id) || {}).name || null, sname = id => (S.suppliers.get(id) || {}).name || null;
      return {
        label: cl ? cl.label : "السنة الحالية (غير مقفلة)", closed: !!cl, shop: S.settings.shop_name, printed_at: this.ts(), closed_at: cl ? cl.ts : null,
        from: (all[0] || "").slice(0, 10), to: cl ? cl.ts.slice(0, 10) : this.today(),
        summary: pd.summary, months: pd.months, top_products: pd.top,
        sales: pd.sales.map(x => ({ number: x.number, ts: x.ts, customer: x.customerId ? cname(x.customerId) : null, currency: x.currency, total: x.total, paid: x.paid, remaining: r2(x.total - x.paid) })),
        purchases: pd.purchases.map(x => ({ ts: x.ts, supplier: x.supplierId ? sname(x.supplierId) : null, invoice_no: x.invoiceNo, currency: x.currency, total: x.total, paid: x.paid })),
        expenses: pd.expenses.map(x => ({ ts: x.ts, category: x.category, amount: x.amount, currency: x.currency, note: x.note })),
        debts: cl ? cl.debts : debtSnapshot(S), stock: cl ? cl.stock : stockSnapshot(S), cash: cl ? cl.cash : cashSnapshot(S)
      };
    }
    _hash(secret) { return hashSecret(secret); }

    /* ============================== المزامنة ============================== */
    _vecNoSeed() { const v = {}; for (const k of Object.keys(this.vec)) if (k !== "seed") v[k] = this.vec[k]; return v; }
    async _keys() {
      const g = this.meta.group; if (this._kc && this._kc.s === g.secret) return this._kc;
      const base = await crypto.subtle.importKey("raw", b64uDec(g.secret), "HKDF", false, ["deriveBits", "deriveKey"]), salt = te.encode("agri-sync-v1");
      const enc = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info: te.encode("enc") }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
      const auth = toHex(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: te.encode("auth") }, base, 256));
      return (this._kc = { s: g.secret, enc, auth });
    }
    async _seal(ev) {
      const k = await this._keys(), iv = randBytes(12), ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k.enc, te.encode(JSON.stringify(ev))));
      const all = new Uint8Array(12 + ct.length); all.set(iv); all.set(ct, 12); return { dev: ev.dev, seq: ev.seq, b: b64uEnc(all) };
    }
    async _open(env) {
      const k = await this._keys(), all = b64uDec(env.b), pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: all.slice(0, 12) }, k.enc, all.slice(12));
      const ev = JSON.parse(td.decode(pt)); if (ev.dev !== env.dev || ev.seq !== env.seq || ev.dev === "seed") throw new Error("bad envelope"); return ev;
    }
    async _ingest(evs) {
      evs = evs.filter(e => e && e.dev !== "seed" && typeof e.id === "string");
      const added = this._addMany(evs); if (added.length) { await this.store.putEvents(added); this.emit("change", { local: false }); } return added.length;
    }
    async _outgoing(theirVec) {
      const out = []; let more = false; const LIM = 400;
      for (const dev of Object.keys(this.byDev)) {
        if (dev === "seed") continue; const arr = this.byDev[dev];
        for (let i = theirVec[dev] || 0; i < arr.length; i++) { if (out.length >= LIM) { more = true; break; } out.push(arr[i]); }
      }
      const events = []; for (const e of out) events.push(await this._seal(e));
      return { events, vector: this._vecNoSeed(), more };
    }
    /* الطرف المستقبِل (جهاز سطح المكتب كخادم محلي، أو الأندرويد عند الطلب) */
    async handleSyncRequest(req) {
      if (!req || req.v !== 1) throw new ApiError(400, "طلب غير صالح");
      const k = await this._keys(); if (req.gid !== this.meta.group.gid || req.auth !== k.auth) throw new ApiError(403, "غير مصرّح");
      const evs = []; for (const env of req.events || []) { try { evs.push(await this._open(env)); } catch (e) { } }
      if (evs.length) await this._lock(() => this._ingest(evs));
      return this._lock(() => this._outgoing(req.vector || {}));
    }
    async _post(url, body) {
      if (this.transport) return this.transport(url, body);
      const ac = typeof AbortController !== "undefined" ? new AbortController() : null, tm = ac && setTimeout(() => ac.abort(), 10000);
      try {
        const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), signal: ac && ac.signal });
        if (!r.ok) throw new Error("HTTP " + r.status); return await r.json();
      } finally { if (tm) clearTimeout(tm); }
    }
    _syncUrl(u) { u = String(u).trim().replace(/\/+$/, ""); if (!/^https?:\/\//i.test(u)) u = "http://" + u; return u + "/sync"; }
    async _syncOne(url) {
      const k = await this._keys(), gid = this.meta.group.gid; let theirVec = null, sent = 0, got = 0, sendMore = false;
      for (let round = 0; round < 60; round++) {
        let send = []; sendMore = false;
        if (theirVec) { const o = await this._lock(() => this._outgoing(theirVec)); send = o.events; sendMore = o.more; sent += send.length; }
        const res = await this._post(url, { v: 1, gid, auth: k.auth, vector: this._vecNoSeed(), events: send });
        theirVec = res.vector || {};
        const evs = []; for (const env of res.events || []) { try { evs.push(await this._open(env)); } catch (e) { } }
        if (evs.length) got += await this._lock(() => this._ingest(evs));
        if (!res.more && !sendMore && round > 0) break;
        if (!res.more && !sendMore && round === 0) { const need = await this._lock(() => this._outgoing(theirVec)); if (!need.events.length) break; }
      }
      return { sent, got };
    }
    _targets() {
      const t = []; for (const r of this.meta.remotes || []) for (const u of r.urls || []) t.push({ kind: "lan", url: u });
      if (this.meta.relayUrl) t.push({ kind: "relay", url: this.meta.relayUrl }); return t;
    }
    async syncNow() {
      if (this.syncing) return this.syncState; this.syncing = true; const res = { ok: false, results: [], at: null };
      try {
        const lanDone = new Set();
        for (const r of this.meta.remotes || []) {
          let ok = false, last = null;
          for (const u of r.urls || []) { try { const x = await this._syncOne(this._syncUrl(u)); res.results.push({ url: u, ...x }); ok = true; break; } catch (e) { last = e; } }
          if (!ok && (r.urls || []).length) res.results.push({ url: r.urls[0], error: String(last && last.message || last) });
        }
        if (this.meta.relayUrl) { try { const x = await this._syncOne(this._syncUrl(this.meta.relayUrl)); res.results.push({ url: this.meta.relayUrl, ...x }); } catch (e) { res.results.push({ url: this.meta.relayUrl, error: String(e && e.message || e) }); } }
        res.ok = res.results.some(r => !r.error); res.at = this.ts();
        if (res.ok) { this.meta.lastSyncAt = res.at; await this.store.setMeta("meta", this.meta); }
        res.nothing = !res.results.length;
      } finally { this.syncing = false; this.syncState = res; this.emit("sync", res); }
      return res;
    }
    startAuto(ms) {
      this.stopAuto(); const go = () => { if (this._targets().length) this.syncNow().catch(() => { }); };
      this.autoTimer = setInterval(go, ms || 30000);
      this._deb = null; this.on("change", ev => { if (ev && ev.local && this._targets().length) { clearTimeout(this._deb); this._deb = setTimeout(go, 1500); } });
      if (typeof addEventListener === "function") try { addEventListener("online", go); } catch (e) { }
      setTimeout(go, 500);
    }
    stopAuto() { if (this.autoTimer) clearInterval(this.autoTimer); this.autoTimer = null; }

    async _pairingCode() {
      const g = this.meta.group, hosts = await this.getHosts();
      return "AGRI1:" + b64uEnc(te.encode(JSON.stringify([1, g.gid, g.secret, (g.name || this.S.settings.shop_name || "").slice(0, 40), this.meta.relayUrl || "", hosts || []])));
    }
    _parsePairing(code) {
      let a; try { a = JSON.parse(td.decode(b64uDec(String(code).trim().replace(/\s+/g, "").replace(/^AGRI1:/i, "")))); } catch (e) { throw bad("رمز الربط غير صالح"); }
      if (!Array.isArray(a) || a[0] !== 1 || typeof a[1] !== "string" || typeof a[2] !== "string" || a[1].length < 8 || a[2].length < 16) throw bad("رمز الربط غير صالح");
      return { gid: a[1], secret: a[2], name: a[3] || "", relayUrl: a[4] || "", hosts: Array.isArray(a[5]) ? a[5].filter(h => typeof h === "string").slice(0, 8) : [] };
    }
    _peekPairing(body) { const p = this._parsePairing(body.code); return { name: p.name, same: p.gid === this.meta.group.gid, hosts: p.hosts, relay: p.relayUrl }; }
    async _join(code) {
      const p = this._parsePairing(code), same = p.gid === this.meta.group.gid;
      if (!same) { this.meta.group = { gid: p.gid, secret: p.secret, name: p.name }; this.meta.remotes = []; this._kc = null; }
      if (p.relayUrl) this.meta.relayUrl = p.relayUrl;
      if (p.hosts.length) { const key = p.hosts.slice().sort().join(","); this.meta.remotes = (this.meta.remotes || []).filter(r => r.urls.slice().sort().join(",") !== key); this.meta.remotes.push({ type: "lan", urls: p.hosts }); }
      await this.store.setMeta("meta", this.meta); this.emit("change", { local: true, joined: true }); return { ok: true, name: p.name, same };
    }
    async _syncRoute(path, parts, method, body, user) {
      if (path === "info") return this._info();
      if (path === "sync/status") return this._info();
      this._owner();
      if (path === "sync/pairing") return { code: await this._pairingCode(), hosts: await this.getHosts() };
      if (path === "sync/join" && method === "POST") return this._join(body.code);
      if (path === "sync/remote/remove" && method === "POST") { this.meta.remotes = (this.meta.remotes || []).filter(r => !r.urls.includes(body.url)); await this.store.setMeta("meta", this.meta); return this._info(); }
      if (path === "sync/remote/add" && method === "POST") {
        const u = String(body.url || "").trim(); if (!u) throw bad("أدخل العنوان");
        this.meta.remotes = (this.meta.remotes || []); this.meta.remotes.push({ type: "lan", urls: [u] }); await this.store.setMeta("meta", this.meta); return this._info();
      }
      if (path === "sync/relay" && method === "POST") { this.meta.relayUrl = String(body.url || "").trim().replace(/\/+$/, ""); await this.store.setMeta("meta", this.meta); return this._info(); }
      throw new ApiError(404, "مسار غير معروف");
    }
    _info() {
      const g = this.meta.group, n = Object.keys(this.byDev).filter(d => d !== "seed").reduce((a, d) => a + this.byDev[d].length, 0);
      return { deviceId: this.meta.deviceId, devCode: this.devCode, group: { id: g.gid.slice(0, 6).toUpperCase(), name: g.name || "" }, remotes: this.meta.remotes || [], relayUrl: this.meta.relayUrl || "", lastSyncAt: this.meta.lastSyncAt, devices: Object.keys(this.byDev).filter(d => d !== "seed").length, events: n, syncing: this.syncing, last: this.syncState };
    }

    /* ---- الدخول والاستعادة ---- */
    async _login(d) {
      if (Date.now() < this.fails.until) throw new ApiError(429, "محاولات كثيرة، انتظر دقيقة");
      const u = this.S.users.get(d.user_id);
      if (!u || !u.active || !(await checkSecret(normPin(d.pin), u.pin))) {
        this.fails.n++; if (this.fails.n >= 5) { this.fails = { n: 0, until: Date.now() + 60000 }; }
        throw new ApiError(401, "الرمز غير صحيح");
      }
      this.fails = { n: 0, until: 0 }; this.cur = { id: u.id, name: u.name, role: u.role };
      return { token: "local", user: this._userView(u) };
    }
    async _recover(d) {
      if (Date.now() < (this.rfails || { until: 0 }).until) throw new ApiError(429, "محاولات كثيرة، انتظر 5 دقائق");
      const np = normPin(d.new_pin); if (!validPin(np)) throw bad("الرمز الجديد يجب أن يكون أرقاماً (4 إلى 12)");
      const u = this.S.users.get(d.user_id);
      if (!u || !u.active || !u.recovery) throw bad("لا يوجد رمز استعادة لهذا المستخدم. المدير على جهاز آخر يستطيع تغيير رمزك من الإعدادات، أو استخدم «الخيار الأخير».");
      if (!(await checkSecret(normCode(d.code), u.recovery))) {
        const f = this.rfails || { n: 0, until: 0 }; f.n++; if (f.n >= 5) { f.n = 0; f.until = Date.now() + 300000; } this.rfails = f;
        throw new ApiError(403, "رمز الاستعادة غير صحيح");
      }
      this.rfails = { n: 0, until: 0 };
      const code = genRecoveryCode();
      await this._withActor(u, async () => { await this._commit("user.upsert", { id: u.id, pin: await this._hash(np), mustChange: 0, recovery: await this._hash(normCode(code)) }); });
      return { ok: true, recovery_code: code };
    }
    async _withActor(u, fn) { const prev = this.cur; this.cur = { id: u.id, name: u.name, role: u.role }; try { return await fn(); } finally { this.cur = prev; } }
    async _factoryReset(d) {
      if (d.confirm !== "RESET") throw bad("تأكيد غير صحيح");
      await this.store.clearAll(); this.cur = null; this.S = null; this.sorted = []; this.byDev = {}; this.vec = {}; this.maxT = 0; this.syncState = {};
      await this.init(); this.emit("change", { reset: true }); return { ok: true };
    }

    /* ---- سعر الصرف ---- */
    async _setRate(buy, sell, source) {
      if (!(buy >= 10 && buy <= 3000 && sell >= 10 && sell <= 3000)) throw bad("السعر خارج النطاق المنطقي (أدخل سعر الدولار بالليرة الجديدة، مثال 146)");
      if (buy > sell * 1.1) { const a = Math.min(buy, sell), b = Math.max(buy, sell); buy = a; sell = b; }
      await this._commit("rate.set", { ts: this.ts(), buy: r2(buy), sell: r2(sell), source }); return this._rate();
    }
    async _refreshRate(force) {
      const prev = this._rate();
      if (!force && prev && prev.source === "manual") {
        const age = (this.now() - new Date(prev.ts.replace(" ", "T")).getTime()); if (age < 7200000) return prev;       // سعر يدوي حديث لا نكتب فوقه
      }
      let got = null; const errs = [];
      for (const url of ["https://sp-today.com/en", "https://sp-today.com/"]) {
        try { got = parseRateHtml(await this.fetchText(url)); if (got) break; errs.push(url + ": لم أجد السعر بالصفحة"); } catch (e) { errs.push(url + ": " + (e && e.message)); }
      }
      if (!got) throw bad("تعذّر جلب السعر من الليرة اليوم (" + errs.join(" | ") + ")");
      const [buy, sell] = got;
      if (prev && !(0.5 * prev.sell <= sell && sell <= 2 * prev.sell)) throw bad(`السعر المجلوب (${sell}) بعيد جداً عن السعر السابق (${prev.sell}) - لم يُعتمد. أدخله يدوياً إن كان صحيحاً.`);
      if (prev && prev.buy === r2(buy) && prev.sell === r2(sell)) return prev;      // لا تغيير: لا نولّد حدثاً جديداً
      return this._setRate(buy, sell, "sp-today.com");
    }
    /* يُستدعى من الواجهة بدون تسجيل دخول (مؤقت دوري) */
    autoRefreshRate() {
      return this._lock(async () => {
        if (this.S.settings.auto_rate !== "1") return null;
        try { return await this._refreshRate(false); } catch (e) { return null; }
      });
    }

    /* ---- الأصناف ---- */
    _cleanProduct(d, isNew) {
      const out = {};
      for (const k of PFIELDS) if (k in d) {
        let v = d[k];
        if (PNUM.has(k)) { v = parseFloat(v); if (isNaN(v)) v = 0; } else if (typeof v === "string") v = v.trim() || null;
        out[k] = v;
      }
      if (isNew && !out.name) throw bad("اسم الصنف مطلوب");
      if ("name" in out && !out.name) throw bad("اسم الصنف مطلوب");
      if ("pack_factor" in out && out.pack_factor < 1) out.pack_factor = 1;
      if (isNew && !out.unit) out.unit = "قطعة";
      return out;
    }

    /* ---- الزبائن والموردون ---- */
    async _parties(head, parts, method, body, user) {
      const S = this.S, isC = head === "customers", map = isC ? S.customers : S.suppliers, who = isC ? "customer" : "supplier";
      if (parts.length === 1 && method === "GET") {
        const rate = (this._rate() || {}).use || 1;
        return [...map.values()].filter(c => c.active).sort((a, b) => a.name.localeCompare(b.name, "ar")).map(c => {
          const b = this._bal(who, c.id); const d = Object.assign({}, c); delete d.createdT; d.balance = b; d.balance_usd = r2(b.USD + b.SYP / rate); return d;
        });
      }
      if (parts.length === 1 && method === "POST") {
        if (!(body.name || "").trim()) throw bad("الاسم مطلوب"); const id = uuid();
        const d = { id, name: body.name.trim(), phone: body.phone || null, notes: body.notes || null, active: 1 };
        if (isC) { d.village = body.village || null; d.type = body.type || "farmer"; d.credit_limit_usd = +body.credit_limit_usd || 0; }
        await this._commit(isC ? "customer.upsert" : "supplier.upsert", d); return { id };
      }
      if (parts.length === 2 && method === "PUT") {
        if (!map.has(parts[1])) throw new ApiError(404, "غير موجود");
        const cols = ["name", "phone", "notes"].concat(isC ? ["village", "type", "credit_limit_usd"] : []), d = { id: parts[1] };
        for (const k of cols) if (k in body) d[k] = k === "credit_limit_usd" ? (+body[k] || 0) : body[k];
        await this._commit(isC ? "customer.upsert" : "supplier.upsert", d); return { ok: true };
      }
      if (parts.length === 2 && method === "DELETE") { this._owner(); await this._commit(isC ? "customer.delete" : "supplier.delete", { id: parts[1] }); return { ok: true }; }
      if (parts.length === 3 && parts[2] === "statement") {
        return { balance: this._bal(who, parts[1]), rows: S.ledger.filter(x => !x.voided && x.party_type === who && x.party_id === parts[1]).map(x => ({ ts: x.ts, kind: x.kind, amount: x.amount, currency: x.currency, note: x.note, orig_currency: x.orig_currency, orig_amount: x.orig_amount, rate: x.rate })) };
      }
      throw new ApiError(404, "مسار غير معروف");
    }
    async _payment(d, user) {
      const S = this.S, ptype = d.party_type; if (!["customer", "supplier"].includes(ptype)) throw bad("نوع الطرف غير صحيح");
      if (user.role !== "owner" && ptype === "supplier") throw new ApiError(403, "هذه العملية للمدير فقط");
      const party = (ptype === "customer" ? S.customers : S.suppliers).get(d.party_id); if (!party) throw bad("الطرف غير موجود");
      const amount = +d.amount || 0; if (amount <= 0) throw bad("المبلغ غير صحيح");
      const payCur = d.pay_currency || "USD", applyCur = d.apply_currency || payCur; if (!CUR.includes(payCur) || !CUR.includes(applyCur)) throw bad("العملة غير صحيحة");
      const rate = +d.rate || this._needRate().use, applied = r2(convert(amount, payCur, applyCur, rate));
      await this._commit("payment.create", { id: uuid(), ts: this.ts(), partyType: ptype, partyId: party.id, partyName: party.name, amount: r2(amount), payCur, applyCur, applied, rate, note: d.note || "" });
      return this._bal(ptype, party.id);
    }

    /* ---- المبيعات ---- */
    async _createSale(d, edit) {
      const S = this.S, id0 = !edit && d.uuid ? String(d.uuid) : null;
      if (id0 && S.sales.has(id0)) { const r = this._saleDetail(id0); r.duplicate = true; return r; }
      const cur = d.currency || "USD"; if (!CUR.includes(cur)) throw bad("العملة غير صحيحة");
      const items = d.items || []; if (!items.length) throw bad("الفاتورة فارغة");
      const rinfo = this._needRate(); let rate = +d.rate || rinfo.use; if (!(rate >= 10 && rate <= 3000)) rate = rinfo.use;
      const allowNeg = S.settings.allow_negative_stock === "1";
      const cust = d.customer_id ? S.customers.get(d.customer_id) : null; if (d.customer_id && !cust) throw bad("الزبون غير موجود");
      let subtotal = 0; const lines = [], need = new Map();
      for (const it of items) {
        const p = S.products.get(it.product_id); if (!p) throw bad("صنف غير موجود في الفاتورة");
        const qty = +it.qty || 0, price = +it.price || 0; const uo = unitOf(p, it.unit || "base"), unit = uo.key;
        if (qty <= 0 || price < 0) throw bad(`كمية/سعر غير صحيح للصنف «${p.name}»`);
        const base = qty * uo.f, line = r2(price * qty);
        need.set(p.id, (need.get(p.id) || 0) + base);
        if (!allowNeg && stockOf(S, p.id) + (edit ? edit.items.filter(x => x.productId === p.id).reduce((a, x) => a + x.qtyBase, 0) : 0) < need.get(p.id) - 1e-9) throw bad(`الكمية غير كافية للصنف «${p.name}»`);
        lines.push({ productId: p.id, qty, unit, price, base: Math.round(base * 1e6) / 1e6, line }); subtotal += line;
      }
      const discount = Math.max(0, +d.discount || 0), total = r2(Math.max(0, subtotal - discount));
      let paid = d.paid == null ? total : Math.max(0, Math.min(+d.paid, total)); const remaining = r2(total - paid);
      if (remaining > 0.005 && !cust) throw bad("البيع بالدين يحتاج اختيار زبون");
      let over = false; if (cust && remaining > 0.005 && (cust.credit_limit_usd || 0) > 0) over = this._debtUsd(cust.id, rate) - (edit && edit.customerId === cust.id ? toUsd(edit.total - edit.paid, edit.currency, rate) : 0) + toUsd(remaining, cur, rate) > cust.credit_limit_usd + 1e-6;
      const id = id0 || uuid(), n = ((S.devCounts[this.meta.deviceId] || { sale: 0 }).sale) + 1;
      await this._commit(edit ? "sale.edit" : "sale.create", { id, replaces: edit ? edit.id : undefined, number: edit ? edit.number : this.devCode + "-" + String(n).padStart(4, "0"), ts: edit ? edit.ts : (d.ts || this.ts()), customerId: cust ? cust.id : null, currency: cur, rate, items: lines, subtotal: r2(subtotal), discount: r2(discount), total, paid: r2(paid), totalUsd: r2(toUsd(total, cur, rate)), note: d.note || "" });
      const r = this._saleDetail(id); r.over_credit_limit = over; return r;
    }
    _saleDetail(id) {
      const S = this.S, s = S.sales.get(id); if (!s) throw new ApiError(404, "الفاتورة غير موجودة");
      const c = s.customerId ? S.customers.get(s.customerId) : null, u = S.users.get(s.userId), groups = new Map();
      for (const it of s.items) { const k = it.productId + "|" + it.unit + "|" + it.price; const g = groups.get(k) || { product_id: it.productId, sold_unit: it.unit, price: it.price, qty_unit: 0, line_total: 0 }; g.qty_unit = r3(g.qty_unit + it.qtyUnit); g.line_total = r2(g.line_total + it.lineTotal); groups.set(k, g); }
      const items = [...groups.values()].map(g => { const p = S.products.get(g.product_id) || {}; return Object.assign(g, { name: p.name, unit: p.unit, pack_unit: p.pack_unit, unit_label: p.unit ? unitOf(p, g.sold_unit).label : "" }); });
      return { id: s.id, number: s.number, ts: s.ts, customer_id: s.customerId, customer_name: c ? c.name : null, user_name: u ? u.name : null, currency: s.currency, rate: s.rate, subtotal: s.subtotal, discount: s.discount, total: s.total, paid: s.paid, total_usd: s.totalUsd, cost_usd: s.costUsd, note: s.note, voided: s.voided, archived: s.archived ? 1 : 0, edited: s.editedFrom ? 1 : 0, items, remaining: r2(s.total - s.paid) };
    }
    _range(q, full) { const f = (q.from || (full ? "0000-01-01" : this.today())), t = (q.to || (full ? "9999-12-31" : this.today())); return [f + " 00:00:00", t + " 23:59:59"]; }
    _salesList(q) {
      const S = this.S, [f, t] = q.from ? this._range(q) : ["0000", "9999"], lim = Math.min(+q.limit || 200, 1000);
      return S.salesOrder.slice().reverse().map(id => S.sales.get(id)).filter(s => !s.voided && !s.archived && s.ts >= f && s.ts <= t && (!q.customer_id || s.customerId === q.customer_id)).slice(0, lim)
        .map(s => ({ id: s.id, number: s.number, ts: s.ts, currency: s.currency, total: s.total, paid: s.paid, total_usd: s.totalUsd, voided: s.voided, customer_id: s.customerId, customer_name: s.customerId ? (S.customers.get(s.customerId) || {}).name : null }));
    }

    /* ---- المشتريات ---- */
    async _createPurchase(d) {
      const S = this.S, cur = d.currency || "USD"; if (!CUR.includes(cur)) throw bad("العملة غير صحيحة");
      const items = d.items || []; if (!items.length) throw bad("فاتورة الشراء فارغة");
      const rate = +d.rate || this._needRate().use, sup = d.supplier_id ? S.suppliers.get(d.supplier_id) : null; if (d.supplier_id && !sup) throw bad("المورد غير موجود");
      let total = 0; const lines = [];
      for (const it of items) {
        const p = S.products.get(it.product_id); if (!p) throw bad("صنف غير موجود");
        const qty = +it.qty || 0, cost = +it.cost || 0, uo = unitOf(p, it.unit || "base"), unit = uo.key;
        if (qty <= 0 || cost < 0) throw bad(`كمية/تكلفة غير صحيحة للصنف «${p.name}»`);
        const base = qty * uo.f, line = r2(cost * qty); total += line;
        let expiry = (it.expiry || "").trim() || null;
        if (expiry && !/^\d{4}-\d{2}(-\d{2})?$/.test(expiry)) throw bad("صيغة تاريخ الصلاحية: YYYY-MM-DD");
        if (expiry && expiry.length === 7) expiry += "-28";
        lines.push({ productId: p.id, qty, unit, cost, base: r3(base), line, costBaseUsd: Math.round(toUsd(cost, cur, rate) * qty / base * 10000) / 10000, expiry, batchNo: (it.batch_no || "").trim() || null, batchId: uuid() });
      }
      const discount = Math.max(0, +d.discount || 0); total = r2(Math.max(0, total - discount));
      const paid = d.paid == null ? total : Math.max(0, Math.min(+d.paid, total)), remaining = r2(total - paid);
      if (remaining > 0.005 && !sup) throw bad("الشراء بالدين يحتاج اختيار مورد");
      const id = uuid();
      await this._commit("purchase.create", { id, ts: this.ts(), supplierId: sup ? sup.id : null, invoiceNo: d.invoice_no || "", currency: cur, rate, items: lines, discount: r2(discount), total, paid: r2(paid), totalUsd: r2(toUsd(total, cur, rate)), note: d.note || "" });
      return { id, total, paid: r2(paid), remaining, currency: cur };
    }
    _purchView(p) { const sup = p.supplierId ? this.S.suppliers.get(p.supplierId) : null; return { id: p.id, ts: p.ts, supplier_name: sup ? sup.name : null, invoice_no: p.invoiceNo, currency: p.currency, total: p.total, paid: p.paid, total_usd: p.totalUsd, rate: p.rate }; }

    /* ---- المستخدمون ---- */
    async _users(parts, method, body, me) {
      const S = this.S;
      if (parts.length === 1 && method === "GET") return [...S.users.values()].sort((a, b) => a.createdT - b.createdT).map(u => ({ id: u.id, name: u.name, role: u.role, active: u.active ? 1 : 0 }));
      if (parts.length === 1 && method === "POST") {
        const pin = normPin(body.pin); if (!(body.name || "").trim() || !validPin(pin)) throw bad("الاسم مطلوب والرمز أرقام (4 إلى 12)");
        if ([...S.users.values()].some(u => u.name.trim().toLowerCase() === body.name.trim().toLowerCase())) throw bad("الاسم مستخدم");
        const id = uuid(); await this._commit("user.upsert", { id, name: body.name.trim(), role: body.role === "owner" ? "owner" : "cashier", active: 1, mustChange: 0, pin: await this._hash(pin) }); return { id };
      }
      if (parts.length === 2 && method === "PUT") {
        const u = S.users.get(parts[1]); if (!u) throw new ApiError(404, "غير موجود"); const d = { id: u.id };
        if (body.pin) { const pin = normPin(body.pin); if (!validPin(pin)) throw bad("الرمز أرقام (4 إلى 12)"); d.pin = await this._hash(pin); d.mustChange = 0; }
        if ("active" in body) { if (u.id === me.id && !body.active) throw bad("لا يمكنك تعطيل حسابك"); d.active = body.active ? 1 : 0; }
        if ("role" in body && u.id !== me.id) d.role = body.role === "owner" ? "owner" : "cashier";
        await this._commit("user.upsert", d); return { ok: true };
      }
      throw new ApiError(404, "مسار غير معروف");
    }

    /* ---- التقارير ---- */
    _dashboard(user) {
      const S = this.S, rinfo = this._rate(), td = this.today(), month = td.slice(0, 8) + "01";
      const agg = from => { let n = 0, rev = 0, pr = 0; for (const s of S.sales.values()) if (!s.voided && !s.archived && s.ts >= from + " 00:00:00") { n++; rev += s.totalUsd; pr += s.totalUsd - s.costUsd; } return { n, rev, pr }; };
      const a = agg(td), m = agg(month), out = { rate: rinfo, today: { invoices: a.n, revenue_usd: r2(a.rev) }, month: { invoices: m.n, revenue_usd: r2(m.rev) } };
      if (user.role === "owner") {
        out.today.profit_usd = r2(a.pr); out.month.profit_usd = r2(m.pr);
        if (rinfo) { out.customer_debts_usd = this._reportDebts("customer").total_usd; out.supplier_debts_usd = this._reportDebts("supplier").total_usd; }
        const st = this._reportStock({}); out.low_stock = st.low_stock.length; out.expiring = st.expiring.length; out.inventory_value_usd = st.inventory_value_usd;
        out.cash_balance = this._cashBalance();
      }
      return out;
    }
    _cashBalance(f, t) { const b = {}; for (const c of this.S.cash) if (!c.voided && (!f || (c.ts >= f && c.ts <= t))) b[c.currency] = (b[c.currency] || 0) + c.amount; for (const k of Object.keys(b)) b[k] = r2(b[k]); return b; }
    _reportSummary(q) {
      const S = this.S, [f, t] = this._range(q), rate = this._needRate().use, sales = [...S.sales.values()].filter(s => !s.voided && !s.archived && s.ts >= f && s.ts <= t);
      let rev = 0, cost = 0; const byCur = {}, days = new Map(), top = new Map();
      for (const s of sales) {
        rev += s.totalUsd; cost += s.costUsd; const c = byCur[s.currency] || (byCur[s.currency] = { total: 0, paid: 0 }); c.total = r2(c.total + s.total); c.paid = r2(c.paid + s.paid);
        const dk = s.ts.slice(0, 10), dd = days.get(dk) || { day: dk, n: 0, rev_usd: 0, profit_usd: 0 }; dd.n++; dd.rev_usd += s.totalUsd; dd.profit_usd += s.totalUsd - s.costUsd; days.set(dk, dd);
        for (const it of s.items) { const g = top.get(it.productId) || { name: (S.products.get(it.productId) || {}).name, qty: 0, rev_usd: 0, cost_usd: 0 }; g.qty += it.qtyUnit; g.rev_usd += toUsd(it.lineTotal, s.currency, s.rate); g.cost_usd += it.costUsd; top.set(it.productId, g); }
      }
      const exp = S.expenses.filter(e => !e.archived && e.ts >= f && e.ts <= t).reduce((a, e) => a + e.amount_usd, 0);
      return {
        from: f.slice(0, 10), to: t.slice(0, 10), rate, invoices: sales.length, revenue_usd: r2(rev), cost_usd: r2(cost), profit_usd: r2(rev - cost), expenses_usd: r2(exp), net_usd: r2(rev - cost - exp),
        sales_by_currency: byCur, cash_movement: this._cashBalance(f, t), cash_balance: this._cashBalance(),
        top_products: [...top.values()].sort((a, b) => b.rev_usd - a.rev_usd).slice(0, 10).map(g => ({ name: g.name, qty: r3(g.qty), rev_usd: r2(g.rev_usd), profit_usd: r2(g.rev_usd - g.cost_usd) })),
        days: [...days.values()].sort((a, b) => a.day.localeCompare(b.day)).map(d => ({ day: d.day, n: d.n, rev_usd: r2(d.rev_usd), profit_usd: r2(d.profit_usd) }))
      };
    }
    _reportStock(q) {
      const S = this.S, warn = +(q.days || S.settings.expiry_warn_days) || 90, lim = new Date(this.now() + warn * 86400000), limDate = `${lim.getFullYear()}-${pad(lim.getMonth() + 1)}-${pad(lim.getDate())}`;
      const todayMs = new Date(this.today() + "T00:00:00").getTime(); const prods = [], low = [], expiring = []; let value = 0;
      for (const p of [...S.products.values()].filter(p => p.active).sort((a, b) => a.name.localeCompare(b.name, "ar"))) {
        const bs = S.batchesByProduct.get(p.id) || [], stock = stockOf(S, p.id), val = bs.reduce((a, b) => a + b.qtyRemaining * b.costUsd, 0); value += val;
        if (p.min_stock > 0 && stock <= p.min_stock) low.push({ id: p.id, name: p.name, category: p.category, unit: p.unit, min_stock: p.min_stock, cost_usd: p.cost_usd, stock, value_usd: val });
        if (stock > 0) prods.push({ id: p.id, name: p.name, category: p.category, unit: p.unit, stock, value_usd: r2(val) });
        for (const b of bs) if (b.qtyRemaining > 0 && b.expiry && b.expiry <= limDate) expiring.push({ batch_id: b.id, product_id: p.id, name: p.name, unit: p.unit, batch_no: b.batchNo, expiry: b.expiry, qty_remaining: b.qtyRemaining, days_left: Math.floor((new Date(b.expiry + "T00:00:00").getTime() - todayMs) / 86400000) });
      }
      expiring.sort((a, b) => a.expiry.localeCompare(b.expiry));
      return { inventory_value_usd: r2(value), low_stock: low, expiring, warn_days: warn, products: prods };
    }
    _reportDebts(who) {
      const S = this.S, rate = this._needRate().use, rows = [];
      for (const p of [...(who === "customer" ? S.customers : S.suppliers).values()].filter(p => p.active).sort((a, b) => a.name.localeCompare(b.name, "ar"))) {
        const b = this._bal(who, p.id); if (Math.abs(b.USD) > 0.004 || Math.abs(b.SYP) > 0.004) {
          let last = null; for (const x of S.ledger) if (!x.voided && x.party_type === who && x.party_id === p.id && x.kind === "payment" && (!last || x.ts > last)) last = x.ts;
          rows.push({ id: p.id, name: p.name, phone: p.phone, USD: b.USD, SYP: b.SYP, total_usd: r2(b.USD + b.SYP / rate), last_payment: last });
        }
      }
      rows.sort((a, b) => b.total_usd - a.total_usd); return { rate, rows, total_usd: r2(rows.reduce((a, r) => a + r.total_usd, 0)) };
    }
  }

  /* ---------- وحدات البيع (لتر/نص لتر/مل، كغ/غ، متر/سم) ---------- */
  const UNAME = { "لتر": ["vol", 1000], "ليتر": ["vol", 1000], "مل": ["vol", 1], "كغ": ["mass", 1000], "كغم": ["mass", 1000], "كلغ": ["mass", 1000], "كيلو": ["mass", 1000], "غ": ["mass", 1], "غرام": ["mass", 1], "غم": ["mass", 1], "متر": ["len", 100], "م": ["len", 100], "سم": ["len", 1] };
  const UPRE = { vol: [["لتر", 1000], ["نص لتر", 500], ["ربع لتر", 250], ["100 مل", 100], ["مل", 1]], mass: [["كغ", 1000], ["نص كغ", 500], ["ربع كغ", 250], ["100 غ", 100], ["غ", 1]], len: [["متر", 100], ["نص متر", 50], ["سم", 1]] };
  function unitsFor(p) {
    const out = [{ key: "base", label: p.unit || "قطعة", f: 1 }], b = UNAME[String(p.unit || "").trim()];
    if (b) for (const [label, amt] of UPRE[b[0]]) if (amt !== b[1]) out.push({ key: "u" + amt, label, f: amt / b[1] });
    if (p.pack_unit) {
      out.push({ key: "pack", label: p.pack_unit, f: p.pack_factor || 1 });
      const word = String(p.pack_unit).split(" ")[0], seen = new Set([p.pack_factor || 1]);
      for (const t of String(p.packs || "").split(/[,،\s]+/)) { const n = parseFloat(normDigits(t)); if (n > 0 && !seen.has(n)) { seen.add(n); out.push({ key: "pk" + n, label: word + " " + n + " " + (p.unit || ""), f: n }); } }
    }
    return out;
  }
  const unitOf = (p, key) => unitsFor(p).find(u => u.key === key) || unitsFor(p)[0];

  const exported = { unitsFor, UNIT_NAMES: Object.keys(UNAME), create: async opts => { const e = new Engine(opts); await e.init(); return e; }, Engine, MemoryStore, ApiError, parseRateHtml, normDigits, normPin, normCode, b64uEnc, b64uDec, toHex, fromHex, randId, uuid, pbkdf2Hex, cmpEv, fmtTs, DEFAULTS, _internals: { APPLY, newState } };
  return exported;
});
