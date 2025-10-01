// pages/api/verify-recaptcha-and-ip.js
export default async function handler(req, res) {
  // CORS seguro para seu domínio Blogspot
  res.setHeader('Access-Control-Allow-Origin', 'https://www.totalcursos.com.br');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Responde preflight OPTIONS
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).end();

  const { token, ip: ipBody } = req.body || {};
  if (!token) return res.status(400).json({ error: 'Missing token' });

  const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET || '';
  const IPQS_KEY = process.env.IPQS_KEY || '';
  const ABUSE_KEY = process.env.ABUSEIPDB_KEY || '';

  // pegar IP: aceita ip no body (útil para testes), senão usa header/socket
  const getClientIp = (req) => {
  const ipFromBody = req.body?.ip;
  if (ipFromBody) return ipFromBody;      // <-- usa IP de teste se fornecido
  const header = req.headers['x-forwarded-for'] || req.headers['x-real-ip'];
  if (header) return header.split(',')[0].trim();
  return req.socket?.remoteAddress || null;
  };
  
  const ip = getClientIp(req);
  if (!ip) return res.status(400).json({ error: 'Missing IP' });

  // ------- Simple in-memory cache (per instance). TTL 10 min -------
  // Nota: serverless pode reiniciar — cache não persiste entre instâncias.
  if (!global.__ipReputationCache) {
    global.__ipReputationCache = new Map();
  }
  const cache = global.__ipReputationCache;
  const CACHE_TTL_MS = 1000 * 60 * 10; // 10 minutos

  function cacheGet(key) {
    const row = cache.get(key);
    if (!row) return null;
    if (Date.now() > row.expires) {
      cache.delete(key);
      return null;
    }
    return row.value;
  }
  function cacheSet(key, value) {
    cache.set(key, { value, expires: Date.now() + CACHE_TTL_MS });
  }

  // ------- Helpers para chamadas externas -------
  async function verifyRecaptcha(token) {
    const params = new URLSearchParams();
    params.append('secret', RECAPTCHA_SECRET);
    params.append('response', token);

    try {
      const r = await fetch('https://www.google.com/recaptcha/api/siteverify', {
        method: 'POST',
        body: params
      });
      if (!r.ok) return { error: 'recaptcha_http_' + r.status };
      const json = await r.json();
      return { success: Boolean(json.success), score: Number(json.score ?? 0), action: json.action ?? null, raw: json };
    } catch (err) {
      return { error: String(err) };
    }
  }

  async function fetchIPQS(ip) {
    const key = `ipqs:${ip}`;
    const cached = cacheGet(key);
    if (cached) return cached;

    if (!IPQS_KEY) return { error: 'no_ipqs_key', fallback: true };

    try {
      const url = `https://ipqualityscore.com/api/json/ip/${IPQS_KEY}/${ip}`;
      const r = await fetch(url, { timeout: 7000 });
      if (!r.ok) {
        if (r.status === 429) return { error: 'rate_limited', fallback: true };
        return { error: 'http_' + r.status, fallback: true };
      }
      const json = await r.json();
      cacheSet(key, json);
      return json;
    } catch (err) {
      return { error: String(err), fallback: true };
    }
  }

  async function fetchAbuse(ip) {
    const key = `abuse:${ip}`;
    const cached = cacheGet(key);
    if (cached) return cached;

    if (!ABUSE_KEY) return { error: 'no_abuse_key', fallback: true };

    try {
      const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`;
      const r = await fetch(url, {
        headers: { Key: ABUSE_KEY, Accept: 'application/json' },
        timeout: 7000
      });
      if (!r.ok) {
        if (r.status === 429) return { error: 'rate_limited', fallback: true };
        return { error: 'http_' + r.status, fallback: true };
      }
      const json = await r.json();
      cacheSet(key, json);
      return json;
    } catch (err) {
      return { error: String(err), fallback: true };
    }
  }

  // ------- Combinação de scores / decisão -------
  function combineReputation(ipqs = {}, abuse = {}) {
    const ipqsScore = Number(ipqs.fraud_score ?? ipqs.fraudScore ?? 0);
    const abuseScore = Number(abuse?.data?.abuseConfidenceScore ?? 0);

    const proxy = !!ipqs.proxy;
    const vpn = !!(ipqs.vpn || ipqs.active_vpn);
    const tor = !!ipqs.tor;
    const bot_status = !!ipqs.bot_status;

    let combined = Math.round(ipqsScore * 0.6 + abuseScore * 0.4);
    if (proxy || vpn || tor || bot_status) combined = Math.min(100, combined + 20);

    let reputationVerdict = 'UNKNOWN';
    if (combined >= 80) reputationVerdict = 'BOT';
    else if (combined >= 55) reputationVerdict = 'SUSPECT';
    else if (combined >= 40) reputationVerdict = 'UNSURE';
    else reputationVerdict = 'CLEAN';

    return { combined, reputationVerdict, ipqsScore, abuseScore, proxy, vpn, tor, bot_status };
  }

  try {
    // executar em paralelo: reCAPTCHA + IP checks
    const [recaptchaResult, ipqsResult, abuseResult] = await Promise.all([
      verifyRecaptcha(token),
      fetchIPQS(ip),
      fetchAbuse(ip)
    ]);

    const rep = combineReputation(ipqsResult || {}, abuseResult || {});

    // lógica final para dizer "mais provável humano ou bot"
    // regra: recaptcha score >= 0.7 tende a humano; baixa reputação (rep.combined >= 55) tende a bot
    let finalVerdict = 'UNKNOWN';
    let humanConfidence = 0; // 0..100

    // base a partir do recaptcha
    const recScore = Number(recaptchaResult.score ?? 0);
    if (recaptchaResult.success && recScore >= 0.7) humanConfidence = Math.round(recScore * 100);
    else humanConfidence = Math.round(recScore * 100 * 0.6); // penaliza se falha

    // ajuste por reputação
    // se reputação indica bot (alta), reduz a confiança humana
    const repPenalty = Math.round((rep.combined / 100) * 100); // 0..100
    const adjustedHumanConfidence = Math.max(0, humanConfidence - repPenalty * 0.6);

    // decisão final simples
    if (adjustedHumanConfidence >= 60 && rep.combined < 55) finalVerdict = 'HUMAN';
    else if (rep.combined >= 80 || adjustedHumanConfidence < 20) finalVerdict = 'BOT';
    else finalVerdict = 'SUSPECT';

    // resposta final
    const out = {
      ip,
      timestamp: new Date().toISOString(),
      recaptcha: {
        success: Boolean(recaptchaResult.success),
        score: Number(recaptchaResult.score ?? 0),
        action: recaptchaResult.action ?? null,
        raw: recaptchaResult.raw ?? null,
        error: recaptchaResult.error ?? null
      },
      ip_reputation: {
        combinedScore: rep.combined,
        verdict: rep.reputationVerdict,
        ipqsScore: rep.ipqsScore,
        abuseScore: rep.abuseScore,
        flags: { proxy: rep.proxy, vpn: rep.vpn, tor: rep.tor, bot_status: rep.bot_status },
        raw_ipqs: ipqsResult,
        raw_abuseipdb: abuseResult
      },
      final: {
        verdict: finalVerdict,
        adjustedHumanConfidence: Math.round(adjustedHumanConfidence),
        humanConfidenceRaw: humanConfidence
      }
    };

    return res.status(200).json(out);
  } catch (err) {
    console.error('verify-and-ip error:', err);
    return res.status(500).json({ error: 'Verification failed', detail: String(err) });
  }
}
