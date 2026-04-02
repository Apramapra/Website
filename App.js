// app.js - Single file full stack earning platform
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const crypto = require('crypto');

const app = express();

// ==================== CONFIGURATION ====================
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_change_me';
const AROLINKS_API_KEY = process.env.AROLINKS_API_KEY || 'be1b1022b77bc5681c03c305bfa1f971910ee34d';
const SITE_URL = process.env.SITE_URL || 'http://localhost:3000';
const DEFAULT_EARN_AMOUNT = 1.00;

// ==================== MIDDLEWARE ====================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ==================== DATABASE MODELS ====================
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  balance: { type: Number, default: 0 },
  upiId: { type: String, default: '' },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  createdAt: { type: Date, default: Date.now }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});
userSchema.methods.comparePassword = async function(candidate) {
  return await bcrypt.compare(candidate, this.password);
};
const User = mongoose.model('User', userSchema);

const linkSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  randomCode: { type: String, required: true, unique: true },
  earnUrl: { type: String, required: true },
  shortUrl: { type: String, required: true },
  status: { type: String, enum: ['pending', 'used'], default: 'pending' },
  amountEarned: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  usedAt: { type: Date }
});
const Link = mongoose.model('Link', linkSchema);

const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  type: { type: String, enum: ['credit', 'debit'], required: true },
  description: { type: String, required: true },
  linkId: { type: mongoose.Schema.Types.ObjectId, ref: 'Link' },
  createdAt: { type: Date, default: Date.now }
});
const Transaction = mongoose.model('Transaction', transactionSchema);

const withdrawalSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  upiId: { type: String, required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  requestedAt: { type: Date, default: Date.now },
  processedAt: { type: Date }
});
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

const configSchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  value: { type: mongoose.Schema.Types.Mixed, required: true }
});
const Config = mongoose.model('Config', configSchema);

// ==================== AUTH MIDDLEWARE ====================
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) return res.redirect('/login');
    req.user = user;
    next();
  } catch (err) {
    res.redirect('/login');
  }
};

const adminMiddleware = (req, res, next) => {
  if (req.user && req.user.role === 'admin') return next();
  res.status(403).send('Admin access only');
};

// ==================== INITIALIZE DEFAULTS ====================
async function initDefaults() {
  const adminExists = await User.findOne({ role: 'admin' });
  if (!adminExists) {
    await User.create({
      username: 'admin',
      email: 'admin@example.com',
      password: 'admin123',
      role: 'admin'
    });
    console.log('Admin created: admin@example.com / admin123');
  }
  const earnConfig = await Config.findOne({ key: 'earnAmount' });
  if (!earnConfig) {
    await Config.create({ key: 'earnAmount', value: DEFAULT_EARN_AMOUNT });
  }
}

// ==================== ROUTES ====================

// ----- Login / Register -----
app.get('/login', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html><head><title>Login</title><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-gray-100 flex items-center justify-center min-h-screen">
      <div class="bg-white p-8 rounded shadow-md w-96">
        <h2 class="text-2xl font-bold mb-6">Login</h2>
        <form method="POST" action="/login">
          <input type="email" name="email" placeholder="Email" class="w-full p-2 border rounded mb-4" required>
          <input type="password" name="password" placeholder="Password" class="w-full p-2 border rounded mb-4" required>
          <button type="submit" class="w-full bg-blue-600 text-white py-2 rounded">Login</button>
        </form>
        <p class="mt-4 text-center">No account? <a href="/register" class="text-blue-600">Register</a></p>
      </div>
    </body></html>
  `);
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await user.comparePassword(password))) {
    return res.send('<script>alert("Invalid credentials"); window.location="/login";</script>');
  }
  const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true });
  res.redirect(user.role === 'admin' ? '/admin' : '/dashboard');
});

app.get('/register', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html><head><title>Register</title><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-gray-100 flex items-center justify-center min-h-screen">
      <div class="bg-white p-8 rounded shadow-md w-96">
        <h2 class="text-2xl font-bold mb-6">Register</h2>
        <form method="POST" action="/register">
          <input type="text" name="username" placeholder="Username" class="w-full p-2 border rounded mb-4" required>
          <input type="email" name="email" placeholder="Email" class="w-full p-2 border rounded mb-4" required>
          <input type="password" name="password" placeholder="Password" class="w-full p-2 border rounded mb-4" required>
          <input type="password" name="confirmPassword" placeholder="Confirm Password" class="w-full p-2 border rounded mb-4" required>
          <button type="submit" class="w-full bg-blue-600 text-white py-2 rounded">Register</button>
        </form>
        <p class="mt-4 text-center">Already have an account? <a href="/login" class="text-blue-600">Login</a></p>
      </div>
    </body></html>
  `);
});

app.post('/register', async (req, res) => {
  const { username, email, password, confirmPassword } = req.body;
  if (password !== confirmPassword) return res.send('<script>alert("Passwords do not match"); window.location="/register";</script>');
  const existing = await User.findOne({ $or: [{ email }, { username }] });
  if (existing) return res.send('<script>alert("User already exists"); window.location="/register";</script>');
  const user = await User.create({ username, email, password });
  const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true });
  res.redirect('/dashboard');
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

// ----- Dashboard (protected) -----
app.get('/dashboard', authMiddleware, async (req, res) => {
  const links = await Link.find({ userId: req.user._id }).sort({ createdAt: -1 }).limit(20);
  const transactions = await Transaction.find({ userId: req.user._id }).sort({ createdAt: -1 }).limit(10);
  res.send(`
    <!DOCTYPE html>
    <html><head><title>Dashboard</title><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-gray-100">
      <nav class="bg-white shadow p-4 flex justify-between">
        <span class="font-bold text-xl">EarnLinks</span>
        <div class="space-x-4">
          <span>Balance: ₹${req.user.balance.toFixed(2)}</span>
          <a href="/dashboard" class="text-blue-600">Dashboard</a>
          <a href="/profile" class="text-blue-600">Profile</a>
          <a href="/withdrawal" class="text-blue-600">Withdraw</a>
          <a href="/logout" class="text-red-600">Logout</a>
        </div>
      </nav>
      <div class="max-w-4xl mx-auto p-6">
        <div class="bg-white rounded shadow p-6 mb-6">
          <h2 class="text-2xl font-bold mb-4">Generate New Link</h2>
          <button id="genBtn" class="bg-blue-600 text-white px-6 py-2 rounded">Generate Short Link</button>
          <div id="result" class="mt-4 hidden"><input id="shortUrl" class="w-full p-2 border rounded" readonly><button onclick="copyUrl()" class="mt-2 bg-gray-600 text-white px-4 py-1 rounded">Copy</button></div>
          <div id="error" class="mt-4 hidden text-red-600"></div>
        </div>
        <div class="bg-white rounded shadow p-6">
          <h2 class="text-2xl font-bold mb-4">Your Links</h2>
          <table class="w-full"><thead><tr class="bg-gray-100"><th class="p-2 text-left">Short URL</th><th>Status</th><th>Created</th><th>Earned</th></tr></thead><tbody>
            ${links.map(link => `<tr><td class="p-2"><a href="${link.shortUrl}" target="_blank" class="text-blue-600">${link.shortUrl}</a></td><td class="p-2">${link.status}</td><td class="p-2">${link.createdAt.toLocaleDateString()}</td><td class="p-2">₹${link.amountEarned.toFixed(2)}</td></tr>`).join('')}
            ${links.length === 0 ? '<tr><td colspan="4" class="text-center p-4">No links yet</td></tr>' : ''}
          </tbody></table>
        </div>
      </div>
      <script>
        document.getElementById('genBtn').onclick = async () => {
          const btn = document.getElementById('genBtn');
          btn.disabled = true; btn.innerText = 'Generating...';
          try {
            const res = await fetch('/api/generate-link', { method: 'POST' });
            const data = await res.json();
            if (data.success) {
              document.getElementById('shortUrl').value = data.shortUrl;
              document.getElementById('result').classList.remove('hidden');
              document.getElementById('error').classList.add('hidden');
              setTimeout(() => location.reload(), 1500);
            } else throw new Error(data.error);
          } catch(e) {
            document.getElementById('error').innerText = e.message;
            document.getElementById('error').classList.remove('hidden');
          } finally {
            btn.disabled = false; btn.innerText = 'Generate Short Link';
          }
        };
        function copyUrl() { const inp = document.getElementById('shortUrl'); inp.select(); document.execCommand('copy'); alert('Copied!'); }
      </script>
    </body></html>
  `);
});

app.get('/profile', authMiddleware, async (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html><head><title>Profile</title><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-gray-100">
      <nav class="bg-white shadow p-4 flex justify-between">
        <span class="font-bold text-xl">EarnLinks</span><div><a href="/dashboard" class="text-blue-600">Back</a> <a href="/logout" class="text-red-600 ml-4">Logout</a></div>
      </nav>
      <div class="max-w-md mx-auto mt-10 bg-white p-6 rounded shadow">
        <h2 class="text-2xl font-bold mb-6">Profile</h2>
        <form method="POST" action="/profile">
          <label class="block mb-2">Username</label><input value="${req.user.username}" disabled class="w-full p-2 border rounded bg-gray-100 mb-4">
          <label class="block mb-2">Email</label><input value="${req.user.email}" disabled class="w-full p-2 border rounded bg-gray-100 mb-4">
          <label class="block mb-2">UPI ID (GPay/PhonePe/Paytm)</label><input name="upiId" value="${req.user.upiId || ''}" class="w-full p-2 border rounded mb-4">
          <button type="submit" class="w-full bg-blue-600 text-white py-2 rounded">Update</button>
        </form>
      </div>
    </body></html>
  `);
});

app.post('/profile', authMiddleware, async (req, res) => {
  req.user.upiId = req.body.upiId;
  await req.user.save();
  res.redirect('/dashboard');
});

// ----- Withdrawal -----
app.get('/withdrawal', authMiddleware, async (req, res) => {
  const withdrawals = await Withdrawal.find({ userId: req.user._id }).sort({ requestedAt: -1 });
  res.send(`
    <!DOCTYPE html>
    <html><head><title>Withdraw</title><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-gray-100">
      <nav class="bg-white shadow p-4 flex justify-between"><span class="font-bold">EarnLinks</span><a href="/dashboard" class="text-blue-600">Dashboard</a></nav>
      <div class="max-w-2xl mx-auto p-6">
        <div class="bg-white rounded shadow p-6 mb-6">
          <h2 class="text-2xl font-bold mb-4">Request Withdrawal</h2>
          <p class="mb-4">Balance: ₹${req.user.balance.toFixed(2)} (Min ₹10)</p>
          <form method="POST" action="/withdrawal/request">
            <input type="number" step="0.01" name="amount" placeholder="Amount" class="w-full p-2 border rounded mb-4" required>
            <input type="text" name="upiId" placeholder="UPI ID (optional if saved in profile)" class="w-full p-2 border rounded mb-4">
            <button type="submit" class="bg-blue-600 text-white px-6 py-2 rounded">Submit Request</button>
          </form>
        </div>
        <div class="bg-white rounded shadow p-6">
          <h3 class="text-xl font-bold mb-4">Withdrawal History</h3>
          <table class="w-full"><thead><tr><th>Amount</th><th>UPI ID</th><th>Status</th><th>Date</th></tr></thead><tbody>
            ${withdrawals.map(w => `<tr><td>₹${w.amount}</td><td>${w.upiId}</td><td>${w.status}</td><td>${new Date(w.requestedAt).toLocaleDateString()}</td></tr>`).join('')}
          </tbody></table>
        </div>
      </div>
    </body></html>
  `);
});

app.post('/withdrawal/request', authMiddleware, async (req, res) => {
  const amount = parseFloat(req.body.amount);
  const upiId = req.body.upiId || req.user.upiId;
  if (isNaN(amount) || amount < 10) return res.send('<script>alert("Minimum ₹10"); window.location="/withdrawal";</script>');
  if (amount > req.user.balance) return res.send('<script>alert("Insufficient balance"); window.location="/withdrawal";</script>');
  if (!upiId) return res.send('<script>alert("UPI ID required"); window.location="/withdrawal";</script>');
  await Withdrawal.create({ userId: req.user._id, amount, upiId, status: 'pending' });
  res.redirect('/withdrawal');
});

// ----- Earn Page (adds money when link visited) -----
app.get('/earn/:userId', async (req, res) => {
  const { userId } = req.params;
  const randomCode = req.query.user;
  const link = await Link.findOne({ userId, randomCode, status: 'pending' });
  if (!link) {
    return res.send(`<div class="p-8 text-center"><h1>Invalid or used link</h1><a href="/login">Go Home</a></div>`);
  }
  const earnConfig = await Config.findOne({ key: 'earnAmount' });
  const amount = earnConfig ? earnConfig.value : DEFAULT_EARN_AMOUNT;
  link.status = 'used';
  link.usedAt = new Date();
  link.amountEarned = amount;
  await link.save();
  const user = await User.findById(userId);
  user.balance += amount;
  await user.save();
  await Transaction.create({ userId: user._id, amount, type: 'credit', description: `Earned from ${link.shortUrl}`, linkId: link._id });
  res.send(`
    <!DOCTYPE html>
    <html><head><title>Success</title><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-gray-100 flex items-center justify-center min-h-screen">
      <div class="bg-white p-8 rounded shadow text-center">
        <div class="text-green-600 text-6xl mb-4">✓</div>
        <h1 class="text-2xl font-bold text-green-600">Congratulations!</h1>
        <p class="mt-4">₹${amount.toFixed(2)} added to your account balance.</p>
        <a href="/login" class="inline-block mt-6 bg-blue-600 text-white px-6 py-2 rounded">Go to Dashboard</a>
      </div>
    </body></html>
  `);
});

// ----- API for generating shortened links (AJAX) -----
app.post('/api/generate-link', authMiddleware, async (req, res) => {
  try {
    const randomCode = crypto.randomBytes(16).toString('hex');
    const earnUrl = `${SITE_URL}/earn/${req.user._id}?user=${randomCode}`;
    const apiUrl = `https://arolinks.com/api?api=${AROLINKS_API_KEY}&url=${encodeURIComponent(earnUrl)}&format=text`;
    const response = await axios.get(apiUrl);
    const shortUrl = response.data.trim();
    if (!shortUrl || shortUrl.includes('error')) throw new Error('Shortening failed');
    await Link.create({ userId: req.user._id, randomCode, earnUrl, shortUrl });
    res.json({ success: true, shortUrl });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ----- Admin Panel -----
app.get('/admin', authMiddleware, adminMiddleware, async (req, res) => {
  const totalUsers = await User.countDocuments({ role: 'user' });
  const totalLinks = await Link.countDocuments();
  const totalEarnings = await Transaction.aggregate([{ $match: { type: 'credit' } }, { $group: { _id: null, total: { $sum: '$amount' } } }]);
  const pendingWithdrawals = await Withdrawal.countDocuments({ status: 'pending' });
  res.send(`
    <!DOCTYPE html>
    <html><head><title>Admin</title><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-gray-100">
      <nav class="bg-white shadow p-4 flex justify-between"><span class="font-bold">Admin Panel</span><a href="/logout" class="text-red-600">Logout</a></nav>
      <div class="max-w-6xl mx-auto p-6">
        <div class="grid grid-cols-4 gap-4 mb-6">
          <div class="bg-white p-4 rounded shadow">Users: ${totalUsers}</div>
          <div class="bg-white p-4 rounded shadow">Links: ${totalLinks}</div>
          <div class="bg-white p-4 rounded shadow">Total Earnings: ₹${(totalEarnings[0]?.total || 0).toFixed(2)}</div>
          <div class="bg-white p-4 rounded shadow">Pending Withdrawals: ${pendingWithdrawals}</div>
        </div>
        <div class="bg-white rounded shadow p-6 mb-6"><a href="/admin/users" class="text-blue-600 mr-4">Manage Users</a><a href="/admin/withdrawals" class="text-blue-600 mr-4">Withdrawals</a><a href="/admin/settings" class="text-blue-600">Settings</a></div>
      </div>
    </body></html>
  `);
});

app.get('/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const users = await User.find({ role: 'user' });
  res.send(`
    <!DOCTYPE html>
    <html><head><title>Users</title><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-gray-100"><div class="max-w-6xl mx-auto p-6"><a href="/admin" class="text-blue-600 mb-4 inline-block">← Back</a>
    <div class="bg-white rounded shadow p-6"><h2 class="text-2xl font-bold mb-4">Users</h2><table class="w-full"><thead><tr><th>Username</th><th>Email</th><th>Balance</th><th>UPI ID</th><th>Actions</th></tr></thead><tbody>
      ${users.map(u => `<tr><td>${u.username}</td><td>${u.email}</td><td>₹${u.balance.toFixed(2)}</td><td>${u.upiId || '-'}</td>
      <td><form method="POST" action="/admin/users/${u._id}/balance" class="inline"><input type="number" name="amount" step="0.01" placeholder="Amount" class="w-24 p-1 border"><select name="action"><option value="add">+</option><option value="deduct">-</option></select><button type="submit" class="bg-blue-600 text-white px-2 py-1 rounded">Update</button></form></td></tr>`).join('')}
    </tbody></table></div></div></body></html>
  `);
});

app.post('/admin/users/:id/balance', authMiddleware, adminMiddleware, async (req, res) => {
  const user = await User.findById(req.params.id);
  const amount = parseFloat(req.body.amount);
  if (req.body.action === 'add') {
    user.balance += amount;
    await Transaction.create({ userId: user._id, amount, type: 'credit', description: 'Admin adjustment' });
  } else {
    user.balance -= amount;
    await Transaction.create({ userId: user._id, amount, type: 'debit', description: 'Admin adjustment' });
  }
  await user.save();
  res.redirect('/admin/users');
});

app.get('/admin/withdrawals', authMiddleware, adminMiddleware, async (req, res) => {
  const withdrawals = await Withdrawal.find().populate('userId');
  res.send(`
    <!DOCTYPE html>
    <html><head><title>Withdrawals</title><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-gray-100"><div class="max-w-6xl mx-auto p-6"><a href="/admin" class="text-blue-600">← Back</a>
    <div class="bg-white rounded shadow p-6 mt-4"><h2 class="text-2xl font-bold mb-4">Withdrawal Requests</h2><table class="w-full"><thead><tr><th>User</th><th>Amount</th><th>UPI ID</th><th>Status</th><th>Action</th></tr></thead><tbody>
      ${withdrawals.map(w => `<tr><td>${w.userId.username}</td><td>₹${w.amount}</td><td>${w.upiId}</td><td>${w.status}</td>
      <td>${w.status === 'pending' ? `<a href="/admin/withdrawals/${w._id}/approve" class="text-green-600 mr-2">Approve</a><a href="/admin/withdrawals/${w._id}/reject" class="text-red-600">Reject</a>` : '-'}</td></tr>`).join('')}
    </tbody></table></div></div></body></html>
  `);
});

app.get('/admin/withdrawals/:id/:action', authMiddleware, adminMiddleware, async (req, res) => {
  const withdrawal = await Withdrawal.findById(req.params.id).populate('userId');
  if (req.params.action === 'approve') {
    if (withdrawal.userId.balance >= withdrawal.amount) {
      withdrawal.userId.balance -= withdrawal.amount;
      await withdrawal.userId.save();
      await Transaction.create({ userId: withdrawal.userId._id, amount: withdrawal.amount, type: 'debit', description: `Withdrawal to ${withdrawal.upiId}` });
      withdrawal.status = 'approved';
    }
  } else if (req.params.action === 'reject') {
    withdrawal.status = 'rejected';
  }
  withdrawal.processedAt = new Date();
  await withdrawal.save();
  res.redirect('/admin/withdrawals');
});

app.get('/admin/settings', authMiddleware, adminMiddleware, async (req, res) => {
  const earnConfig = await Config.findOne({ key: 'earnAmount' });
  const currentAmount = earnConfig ? earnConfig.value : DEFAULT_EARN_AMOUNT;
  res.send(`
    <!DOCTYPE html>
    <html><head><title>Settings</title><script src="https://cdn.tailwindcss.com"></script></head>
    <body class="bg-gray-100"><div class="max-w-md mx-auto p-6"><a href="/admin" class="text-blue-600">← Back</a>
    <div class="bg-white rounded shadow p-6 mt-4"><h2 class="text-2xl font-bold mb-4">Settings</h2>
    <form method="POST" action="/admin/settings"><label class="block mb-2">Earn Amount per click (₹)</label><input type="number" step="0.01" name="earnAmount" value="${currentAmount}" class="w-full p-2 border rounded mb-4"><button type="submit" class="bg-blue-600 text-white px-6 py-2 rounded">Save</button></form></div></div></body></html>
  `);
});

app.post('/admin/settings', authMiddleware, adminMiddleware, async (req, res) => {
  await Config.findOneAndUpdate({ key: 'earnAmount' }, { value: parseFloat(req.body.earnAmount) }, { upsert: true });
  res.redirect('/admin/settings');
});

// ----- Start Server -----
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/earning_platform')
  .then(async () => {
    await initDefaults();
    app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
  })
  .catch(err => console.error('MongoDB error:', err));