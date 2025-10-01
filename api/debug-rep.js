// pages/api/debug-rep.js
export default async function handler(req, res) {
  // CORS aberto só pro seu domínio (útil no debug). Ajuste se precisar.
  res.setHeader('Access-Control-Allow-Origin', 'https://www.totalcursos.com.br');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method Not Allowed' });

  const IPQS_KEY = process.env.IPQS_KEY || '';
  const ABUSE_KEY = process.env.ABUSEIPDB_KEY || '';

  // pega IP: query ?ip= or x-forwarded-for or socket remote
  const ip = (req.query.ip) ||
             (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
             req.socket.remoteAddress ||
             null;

  if (!ip) return res.status(400).json({ error: 'missing_ip' });

  // helper simples para fetch com timeout
  async function safeFetch(url, opts = {}, timeoutMs = 7000) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const r = await fetch(url, { signal: controller.signal, ...opts });
      clearTimeout(id);
      const text = await r.text();
      try { return { ok: r.ok, status: r.status, body: JSON.parse(text) }; }
      catch(e){ return { ok: r.ok, status: r.status, body: text }; }
    } catch (err) {
      clearTimeout(id);
      return { ok: false, error: String(err) };
    }
  }

  // chama IPQualityScore
  async function callIPQS(ip) {
    if (!IPQS_KEY) return { error: 'no_ipqs_key' };
    const url = `https://ipqualityscore.com/api/json/ip/${IPQS_KEY}/${encodeURIComponent(ip)}`;
    return await safeFetch(url);
  }

  // chama AbuseIPDB
  async function callAbuse(ip) {
    if (!ABUSE_KEY) return { error: 'no_abuse_key' };
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`;
    return await safeFetch(url, { headers: { Key: ABUSE_KEY, Accept: 'application/json' } });
  }

  try {
    const [ipqsRes, abuseRes] = await Promise.all([callIPQS(ip), callAbuse(ip)]);

    // montar resposta resumida + raw
    const ipqsSummary = (ipqsRes && ipqsRes.body) ? {
      fraud_score: ipqsRes.body.fraud_score ?? ipqsRes.body.fraudScore ?? null,
      proxy: Boolean(ipqsRes.body.proxy),
      vpn: Boolean(ipqsRes.body.vpn || ipqsRes.body.active_vpn),
      tor: Boolean(ipqsRes.body.tor),
      bot_status: Boolean(ipqsRes.body.bot_status)
    } : { error: ipqsRes?.error ?? (ipqsRes?.ok === false ? `http_${ipqsRes?.status}` : 'no_data') };

    const abuseSummary = (abuseRes && abuseRes.body && abuseRes.body.data) ? {
      abuseConfidenceScore: abuseRes.body.data.abuseConfidenceScore ?? null,
      totalReports: abuseRes.body.data.totalReports ?? 0,
      lastReportedAt: abuseRes.body.data.lastReportedAt ?? null
    } : { error: abuseRes?.error ?? (abuseRes?.ok === false ? `http_${abuseRes?.status}` : 'no_data') };

    return res.status(200).json({
      ip,
      timestamp: new Date().toISOString(),
      ipqs_raw: ipqsRes,
      abuse_raw: abuseRes,
      ipqs: ipqsSummary,
      abuse: abuseSummary
    });
  } catch (err) {
    console.error('debug-rep error', err);
    return res.status(500).json({ error: 'internal_error', detail: String(err) });
  }
}
