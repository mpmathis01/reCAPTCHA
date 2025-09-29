import fetch from 'node-fetch';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).send('Only POST requests allowed');

  const { token } = req.body;
  if(!token) return res.status(400).json({error: 'Missing token'});

  const secret = process.env.RECAPTCHA_SECRET;

  try {
    const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${secret}&response=${token}`
    });
    const data = await response.json();
    res.status(200).json({ success: data.success, score: data.score, action: data.action });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Verification failed' });
  }
}
