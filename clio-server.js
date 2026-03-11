// ════════════════════════════════════════════════════════
//  CLIO BACKEND — Auth + Payments + AI Proxy + Reminders
//  Deploy on Render.com (free tier)
// ════════════════════════════════════════════════════════
const express = require('express');
const cors    = require('cors');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const Stripe  = require('stripe');
const fetch   = (...args) => import('node-fetch').then(({default: f}) => f(...args));

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

// ── ENV VARS (set these in Render dashboard) ──
const SUPABASE_URL     = process.env.SUPABASE_URL     || '';
const SUPABASE_KEY     = process.env.SUPABASE_KEY     || '';
const JWT_SECRET       = process.env.JWT_SECRET       || 'clio-secret-change-me';
const STRIPE_SECRET    = process.env.STRIPE_SECRET    || '';
const CLAUDE_API_KEY   = process.env.CLAUDE_API_KEY   || '';
const PORT             = process.env.PORT             || 3000;

// Stripe price IDs — create these in your Stripe dashboard
const PLANS = {
  basic:   { priceId: process.env.STRIPE_PRICE_BASIC,   name: 'Basic',   price: 5  },
  pro:     { priceId: process.env.STRIPE_PRICE_PRO,     name: 'Pro',     price: 15 },
  business:{ priceId: process.env.STRIPE_PRICE_BUSINESS,name: 'Business',price: 30 }
};

const supabase = SUPABASE_URL ? createClient(SUPABASE_URL, SUPABASE_KEY) : null;
const stripe   = STRIPE_SECRET ? new Stripe(STRIPE_SECRET) : null;

// ── AUTH MIDDLEWARE ──
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

// ── HEALTH ──
app.get('/health', (_, res) => res.json({ status: 'ok', service: 'Clio Backend' }));

// ════════════════════════════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════════════════════════════

// SIGN UP
app.post('/auth/signup', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'Name, email and password required' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });

  try {
    // Check if email exists
    const { data: existing } = await supabase
      .from('users').select('id').eq('email', email).single();
    if (existing) return res.status(400).json({ error: 'Email already registered' });

    const hashed = await bcrypt.hash(password, 10);

    // Create Stripe customer
    let stripeCustomerId = null;
    if (stripe) {
      const customer = await stripe.customers.create({ email, name });
      stripeCustomerId = customer.id;
    }

    const { data: user, error } = await supabase.from('users').insert({
      name, email,
      password_hash: hashed,
      stripe_customer_id: stripeCustomerId,
      plan: 'free',
      created_at: new Date().toISOString()
    }).select().single();

    if (error) throw error;

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, plan: user.plan } });
  } catch(e) {
    console.error('Signup error:', e);
    res.status(500).json({ error: 'Signup failed: ' + e.message });
  }
});

// SIGN IN
app.post('/auth/signin', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  try {
    const { data: user } = await supabase
      .from('users').select('*').eq('email', email).single();
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid email or password' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, plan: user.plan } });
  } catch(e) {
    res.status(500).json({ error: 'Sign in failed' });
  }
});

// GET CURRENT USER
app.get('/auth/me', auth, async (req, res) => {
  const { data: user } = await supabase
    .from('users').select('id,name,email,plan,created_at').eq('id', req.user.id).single();
  res.json({ user });
});

// ════════════════════════════════════════════════════════
//  PAYMENTS (STRIPE)
// ════════════════════════════════════════════════════════

// Create checkout session
app.post('/payments/checkout', auth, async (req, res) => {
  const { plan, successUrl, cancelUrl } = req.body;
  if (!stripe) return res.status(503).json({ error: 'Payments not configured' });
  if (!PLANS[plan]) return res.status(400).json({ error: 'Invalid plan' });

  const { data: user } = await supabase
    .from('users').select('stripe_customer_id').eq('id', req.user.id).single();

  try {
    const session = await stripe.checkout.sessions.create({
      customer: user.stripe_customer_id,
      payment_method_types: ['card'],
      mode: 'subscription',
      line_items: [{ price: PLANS[plan].priceId, quantity: 1 }],
      success_url: successUrl || 'https://your-app.netlify.app?success=true',
      cancel_url:  cancelUrl  || 'https://your-app.netlify.app?canceled=true',
      metadata: { userId: req.user.id, plan }
    });
    res.json({ url: session.url });
  } catch(e) {
    res.status(500).json({ error: 'Checkout failed: ' + e.message });
  }
});

// Stripe webhook — upgrades user plan after payment
app.post('/payments/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch(e) { return res.status(400).send('Webhook error'); }

  if (event.type === 'checkout.session.completed') {
    const { userId, plan } = event.data.object.metadata;
    await supabase.from('users').update({ plan }).eq('id', userId);
  }
  if (event.type === 'customer.subscription.deleted') {
    const customerId = event.data.object.customer;
    await supabase.from('users').update({ plan: 'free' }).eq('stripe_customer_id', customerId);
  }
  res.json({ received: true });
});

// Get subscription status
app.get('/payments/status', auth, async (req, res) => {
  const { data: user } = await supabase
    .from('users').select('plan,stripe_customer_id').eq('id', req.user.id).single();
  res.json({ plan: user.plan });
});

// Cancel subscription
app.post('/payments/cancel', auth, async (req, res) => {
  if (!stripe) return res.status(503).json({ error: 'Payments not configured' });
  const { data: user } = await supabase
    .from('users').select('stripe_customer_id').eq('id', req.user.id).single();
  try {
    const subs = await stripe.subscriptions.list({ customer: user.stripe_customer_id, limit: 1 });
    if (subs.data.length) await stripe.subscriptions.cancel(subs.data[0].id);
    await supabase.from('users').update({ plan: 'free' }).eq('id', req.user.id);
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ════════════════════════════════════════════════════════
//  AI PROXY (Claude)
// ════════════════════════════════════════════════════════
app.post('/ai/chat', auth, async (req, res) => {
  const { messages, systemPrompt } = req.body;

  // Check plan limits
  const { data: user } = await supabase
    .from('users').select('plan,ai_calls_today,last_ai_date').eq('id', req.user.id).single();

  const limits = { free: 10, basic: 50, pro: 200, business: 1000 };
  const today = new Date().toISOString().split('T')[0];
  const calls = user.last_ai_date === today ? (user.ai_calls_today || 0) : 0;
  const limit = limits[user.plan] || 10;

  if (calls >= limit) {
    return res.status(429).json({
      error: `Daily AI limit reached (${limit} messages on ${user.plan} plan). Upgrade to get more!`,
      upgrade: true
    });
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': CLAUDE_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1000,
        system: systemPrompt || 'You are Clio, a warm and smart personal AI assistant.',
        messages: messages || []
      })
    });

    const data = await response.json();

    // Update call count
    await supabase.from('users').update({
      ai_calls_today: calls + 1,
      last_ai_date: today
    }).eq('id', req.user.id);

    res.json({ reply: data.content?.[0]?.text || 'No response', callsUsed: calls + 1, callsLimit: limit });
  } catch(e) {
    res.status(500).json({ error: 'AI error: ' + e.message });
  }
});

// ════════════════════════════════════════════════════════
//  REMINDERS (cloud sync)
// ════════════════════════════════════════════════════════

// Get all reminders
app.get('/reminders', auth, async (req, res) => {
  const { data } = await supabase
    .from('reminders').select('*').eq('user_id', req.user.id).order('date', { ascending: true });
  res.json({ reminders: data || [] });
});

// Create reminder
app.post('/reminders', auth, async (req, res) => {
  const { title, note, date, time, type, contact } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });

  const { data, error } = await supabase.from('reminders').insert({
    user_id: req.user.id,
    title, note, date, time, type: type || 'remind', contact,
    done: false,
    created_at: new Date().toISOString()
  }).select().single();

  if (error) return res.status(500).json({ error: error.message });
  res.json({ reminder: data });
});

// Update reminder
app.patch('/reminders/:id', auth, async (req, res) => {
  const { data, error } = await supabase
    .from('reminders')
    .update(req.body)
    .eq('id', req.params.id)
    .eq('user_id', req.user.id)
    .select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ reminder: data });
});

// Delete reminder
app.delete('/reminders/:id', auth, async (req, res) => {
  await supabase.from('reminders')
    .delete().eq('id', req.params.id).eq('user_id', req.user.id);
  res.json({ success: true });
});

// ════════════════════════════════════════════════════════
//  ADMIN — see all users (add your own auth here)
// ════════════════════════════════════════════════════════
app.get('/admin/users', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== process.env.ADMIN_KEY) return res.status(403).json({ error: 'Forbidden' });
  const { data } = await supabase
    .from('users').select('id,name,email,plan,created_at').order('created_at', { ascending: false });
  res.json({ users: data, total: data?.length });
});

app.listen(PORT, () => console.log(`🚀 Clio backend running on port ${PORT}`));
