export default async function handler(req, res) {
  // CORS seguro para seu domínio Blogspot
  res.setHeader('Access-Control-Allow-Origin', 'https://www.totalcursos.com.br');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Responde preflight OPTIONS
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).end();

  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Missing token' });

  const secret = process.env.RECAPTCHA_SECRET; // variável de ambiente Vercel
  const params = new URLSearchParams();
  params.append('secret', secret);
  params.append('response', token);

  try {
    const googleRes = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      body: params
    });
    const data = await googleRes.json();
    // retorna apenas score/sucesso/action, sem expor a secret
    return res.status(200).json({ success: data.success, score: data.score, action: data.action });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Verification failed' });
  }
}
