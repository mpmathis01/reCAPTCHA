// pages/api/debug-full.js
export default async function handler(req, res) {
  // CORS seguro para seu domínio
  res.setHeader('Access-Control-Allow-Origin', 'https://www.totalcursos.com.br');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!['GET','POST'].includes(req.method)) return res.status(405).json({ error: 'Method Not Allowed' });

  const IPQS_KEY = process.env.IPQS_KEY || '';
  const ABUSE_KEY = process.env.ABUSEIPDB_KEY || '';
  const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET || '';

  // Captura token do ReCAPTCHA
  let token = req.query.token || (req.body && req.body.token) || '';
  if (!token) token = null;

  // Captura IP
  const ip = req.query.ip || (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || null;
  if (!ip) return res.status(400).json({ error: 'missing_ip' });

  // helper fetch com timeout
  async function safeFetch(url, opts={}, timeoutMs=7000){
    const controller = new AbortController();
    const id = setTimeout(()=>controller.abort(), timeoutMs);
    try{
      const r = await fetch(url, { signal: controller.signal, ...opts });
      clearTimeout(id);
      const text = await r.text();
      try { return { ok: r.ok, status: r.status, body: JSON.parse(text) }; }
      catch(e){ return { ok: r.ok, status: r.status, body: text }; }
    } catch(err){ clearTimeout(id); return { ok:false, error:String(err) }; }
  }

  // --- ReCAPTCHA ---
  let recaptcha = { error: 'no_token_provided' };
  if (token && RECAPTCHA_SECRET) {
    const params = new URLSearchParams();
    params.append('secret', RECAPTCHA_SECRET);
    params.append('response', token);
    recaptcha = await safeFetch('https://www.google.com/recaptcha/api/siteverify', { method: 'POST', body: params });
    if (recaptcha.body) recaptcha = recaptcha.body;
  }

  // --- IPQS ---
  let ipqsSummary = { error: 'no_ipqs_key' };
  if (IPQS_KEY){
    const url = `https://ipqualityscore.com/api/json/ip/${IPQS_KEY}/${encodeURIComponent(ip)}`;
    const ipqsRes = await safeFetch(url);
    if (ipqsRes && ipqsRes.body){
      ipqsSummary = {
        fraud_score: ipqsRes.body.fraud_score ?? ipqsRes.body.fraudScore ?? null,
        proxy: Boolean(ipqsRes.body.proxy),
        vpn: Boolean(ipqsRes.body.vpn || ipqsRes.body.active_vpn),
        tor: Boolean(ipqsRes.body.tor),
        bot_status: Boolean(ipqsRes.body.bot_status)
      };
    }
  }

  // --- AbuseIPDB ---
  let abuseSummary = { error: 'no_abuse_key' };
  if (ABUSE_KEY){
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`;
    const abuseRes = await safeFetch(url, { headers: { Key: ABUSE_KEY, Accept: 'application/json' } });
    if (abuseRes && abuseRes.body && abuseRes.body.data){
      abuseSummary = {
        abuseConfidenceScore: abuseRes.body.data.abuseConfidenceScore ?? null,
        totalReports: abuseRes.body.data.totalReports ?? 0,
        lastReportedAt: abuseRes.body.data.lastReportedAt ?? null
      };
    }
  }

  return res.status(200).json({
    ip,
    timestamp: new Date().toISOString(),
    recaptcha,
    ipqs: ipqsSummary,
    abuse: abuseSummary
  });
}
