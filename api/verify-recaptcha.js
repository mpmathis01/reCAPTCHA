// pages/api/verify-recaptcha-and-ip.js
export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', 'https://www.totalcursos.com.br');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).end();

  const { token, ip: ipBody } = req.body || {};
  if (!token) return res.status(400).json({ error: 'Missing token' });

  const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET || '';
  const IPQS_KEY = process.env.IPQS_KEY || '';
  const ABUSE_KEY = process.env.ABUSEIPDB_KEY || '';

  const getClientIp = (req) => {
    const ipFromBody = req.body?.ip;
    if (ipFromBody) return ipFromBody;
    const header = req.headers['x-forwarded-for'] || req.headers['x-real-ip'];
    if (header) return header.split(',')[0].trim();
    return req.socket?.remoteAddress || null;
  };
  const ip = getClientIp(req);
  if (!ip) return res.status(400).json({ error: 'Missing IP' });

  if (!global.__ipReputationCache) global.__ipReputationCache = new Map();
  const cache = global.__ipReputationCache;
  const CACHE_TTL_MS = 1000 * 60 * 10;

  const cacheGet = (key) => {
    const row = cache.get(key);
    if (!row) return null;
    if (Date.now() > row.expires) { cache.delete(key); return null; }
    return row.value;
  };
  const cacheSet = (key, value) => cache.set(key, { value, expires: Date.now() + CACHE_TTL_MS });

  async function verifyRecaptcha(token) {
    const params = new URLSearchParams();
    params.append('secret', RECAPTCHA_SECRET);
    params.append('response', token);
    try {
      const r = await fetch('https://www.google.com/recaptcha/api/siteverify', { method: 'POST', body: params });
      if (!r.ok) return { error: 'recaptcha_http_' + r.status };
      const json = await r.json();
      return { success: Boolean(json.success), score: Number(json.score ?? 0), action: json.action ?? null, raw: json };
    } catch (err) { return { error: String(err) }; }
  }

  async function fetchIPQS(ip) {
    const key = `ipqs:${ip}`;
    const cached = cacheGet(key);
    if (cached) return cached;
    if (!IPQS_KEY) return { error: 'no_ipqs_key', fallback: true };
    try {
      const url = `https://ipqualityscore.com/api/json/ip/${IPQS_KEY}/${ip}`;
      const r = await fetch(url, { timeout: 7000 });
      if (!r.ok) return { error: 'http_' + r.status, fallback: true };
      const json = await r.json();
      cacheSet(key, json);
      return json;
    } catch (err) { return { error: String(err), fallback: true }; }
  }

  async function fetchAbuse(ip) {
    const key = `abuse:${ip}`;
    const cached = cacheGet(key);
    if (cached) return cached;
    if (!ABUSE_KEY) return { error: 'no_abuse_key', fallback: true };
    try {
      const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`;
      const r = await fetch(url, { headers: { Key: ABUSE_KEY, Accept: 'application/json' }, timeout: 7000 });
      if (!r.ok) return { error: 'http_' + r.status, fallback: true };
      const json = await r.json();
      cacheSet(key, json);
      return json;
    } catch (err) { return { error: String(err), fallback: true }; }
  }

  function combineReputation(ipqs = {}, abuse = {}) {
    const ipqsScoreRaw = ipqs.fraud_score ?? ipqs.fraudScore ?? null;
    const ipqsScore = ipqsScoreRaw !== null ? Number(ipqsScoreRaw) : null;
    const abuseScore = Number(abuse?.data?.abuseConfidenceScore ?? 0);

    const proxy = !!ipqs.proxy;
    const vpn = !!(ipqs.vpn || ipqs.active_vpn);
    const tor = !!ipqs.tor;
    const bot_status = !!ipqs.bot_status;

    let combined = 0;
    if (ipqsScore !== null) combined = Math.round(ipqsScore * 0.6 + abuseScore * 0.4);
    else combined = Math.round(abuseScore * 0.7); // AbuseIPDB peso 70% se IPQS nulo

    if (proxy || vpn || tor || bot_status) combined = Math.min(100, combined + 20);

    let verdict = 'UNKNOWN';
    if (combined >= 80) verdict = 'BOT';
    else if (combined >= 55) verdict = 'SUSPECT';
    else if (combined >= 40) verdict = 'UNSURE';
    else verdict = 'CLEAN';

    return { combined, verdict, ipqsScore, abuseScore, proxy, vpn, tor, bot_status };
  }

  try {
    const [recaptchaResult, ipqsResult, abuseResult] = await Promise.all([
      verifyRecaptcha(token),
      fetchIPQS(ip),
      fetchAbuse(ip)
    ]);

    const rep = combineReputation(ipqsResult || {}, abuseResult || {});

    const recScore = Number(recaptchaResult.score ?? 0);
    let humanConfidence = recaptchaResult.success && recScore >= 0.7 ? Math.round(recScore * 100) : Math.round(recScore * 100 * 0.6);
    const repPenalty = Math.round((rep.combined / 100) * 100);
    const adjustedHumanConfidence = Math.max(0, humanConfidence - repPenalty * 0.6);

    let finalVerdict = 'UNKNOWN';
    if (adjustedHumanConfidence >= 60 && rep.combined < 55) finalVerdict = 'HUMAN';
    else if (rep.combined >= 80 || adjustedHumanConfidence < 20) finalVerdict = 'BOT';
    else finalVerdict = 'SUSPECT';

    return res.status(200).json({
      ip,
      timestamp: new Date().toISOString(),
      recaptcha: { success: recaptchaResult.success, score: recScore, action: recaptchaResult.action, raw: recaptchaResult.raw },
      ipqs: ipqsResult,
      abuse: abuseResult,
      combinedScore: rep.combined,
      humanConfidence: adjustedHumanConfidence,
      finalVerdict
    });
  } catch (err) {
    console.error('verify-and-ip error:', err);
    return res.status(500).json({ error: 'Verification failed', detail: String(err) });
  }
}
