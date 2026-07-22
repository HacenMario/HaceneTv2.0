const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// تحديد حد الطلبات للوقاية من الهجمات
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقيقة
  max: 100, // حد أقصى 100 طلب لكل IP
});
app.use('/api/', limiter);

// ============================================================
// 1.  الاتصال بقاعدة البيانات
// ============================================================
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// ============================================================
// 2.  نماذج (Schemas) قاعدة البيانات
// ============================================================

// نموذج المستخدم
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  xtream: {
    server: { type: String, default: '' },
    username: { type: String, default: '' },
    password: { type: String, default: '' }
  },
  createdAt: { type: Date, default: Date.now }
});

// تشفير كلمة المرور قبل الحفظ
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

const User = mongoose.model('User', userSchema);

// نموذج القنوات (اختياري لتخزين القنوات لكل مستخدم)
// لكننا سنعتمد على جلب القنوات مباشرة من Xtream وقت الطلب.

// ============================================================
// 3.  الدوال المساعدة
// ============================================================

// إنشاء توكن JWT
const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, email: user.email, isAdmin: user.isAdmin },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
};

// التحقق من التوكن
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
};

// التحقق من أن المستخدم مسؤول (Admin)
const isAdmin = (req, res, next) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin access required.' });
  next();
};

// دالة لجلب القنوات من خادم Xtream (تُستخدم للمستخدم العادي والمسؤول على حد سواء)
async function fetchXtreamChannels(server, username, password) {
  const url = `${server}/player_api.php?username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}&action=get_live_streams`;
  try {
    const response = await axios.get(url, { timeout: 10000 });
    if (response.data && Array.isArray(response.data)) {
      return response.data.map(item => ({
        name: item.name || 'بدون اسم',
        category: item.category_name || 'عام',
        stream_id: item.stream_id,
        icon: item.stream_icon || '',
        url: '' // لا نخزن الرابط
      }));
    }
    return [];
  } catch (error) {
    console.error('Error fetching Xtream channels:', error.message);
    throw new Error('Failed to fetch channels from Xtream server.');
  }
}

// ============================================================
// 4.  مسارات (Routes) API
// ============================================================

// --- مسار التجربة (health check) ---
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'IPTV Backend is running.' });
});

// --- تسجيل مستخدم جديد ---
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email and password are required.' });
    }
    // التحقق من أن البريد غير مستخدم
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: 'Email already registered.' });

    const user = new User({ name, email, password });
    await user.save();

    const token = generateToken(user);
    res.status(201).json({
      message: 'User registered successfully.',
      token,
      user: { id: user._id, name: user.name, email: user.email, isAdmin: user.isAdmin, isActive: user.isActive }
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Server error during registration.' });
  }
});

// --- تسجيل الدخول ---
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid email or password.' });

    // تحقق من أن الحساب مفعّل
    if (!user.isActive) {
      return res.status(403).json({ error: 'Your account has been deactivated. Contact admin.' });
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).json({ error: 'Invalid email or password.' });

    const token = generateToken(user);
    res.json({
      message: 'Login successful.',
      token,
      user: { id: user._id, name: user.name, email: user.email, isAdmin: user.isAdmin, isActive: user.isActive }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login.' });
  }
});

// --- الحصول على بيانات المستخدم الحالي (يتطلب توكن) ---
app.get('/api/me', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found.' });
    res.json({ user });
  } catch (error) {
    res.status(500).json({ error: 'Server error.' });
  }
});

// --- جلب القنوات للمستخدم (يتطلب توكن) ---
app.get('/api/channels', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    if (!user.isActive) return res.status(403).json({ error: 'Account is deactivated.' });

    // التحقق من وجود بيانات Xtream
    if (!user.xtream || !user.xtream.server || !user.xtream.username || !user.xtream.password) {
      return res.status(400).json({ error: 'Xtream credentials not configured for this account. Contact admin.' });
    }

    const channels = await fetchXtreamChannels(user.xtream.server, user.xtream.username, user.xtream.password);
    res.json({ channels });
  } catch (error) {
    console.error('Fetch channels error:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch channels.' });
  }
});

// --- (للمسؤول) مسارات إدارة المستخدمين ---

// الحصول على قائمة جميع المستخدمين (للمسؤول فقط)
app.get('/api/admin/users', verifyToken, isAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json({ users });
  } catch (error) {
    res.status(500).json({ error: 'Server error.' });
  }
});

// تحديث بيانات المستخدم (للمسؤول فقط)
app.put('/api/admin/users/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const { name, email, isActive, xtream } = req.body;
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    // لا نسمح بتعديل كلمة المرور عبر هذه الواجهة (يمكن إضافتها لاحقاً)
    if (name) user.name = name;
    if (email) user.email = email;
    if (typeof isActive === 'boolean') user.isActive = isActive;
    if (xtream) {
      // نسمح بتحديث بيانات Xtream كاملة أو جزئية
      if (xtream.server !== undefined) user.xtream.server = xtream.server;
      if (xtream.username !== undefined) user.xtream.username = xtream.username;
      if (xtream.password !== undefined) user.xtream.password = xtream.password;
    }

    await user.save();
    res.json({ message: 'User updated successfully.', user: user.toObject({ getters: true, virtuals: false }) });
  } catch (error) {
    console.error('Admin update user error:', error);
    res.status(500).json({ error: 'Server error.' });
  }
});

// حذف مستخدم (للمسؤول فقط)
app.delete('/api/admin/users/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    res.json({ message: 'User deleted successfully.' });
  } catch (error) {
    res.status(500).json({ error: 'Server error.' });
  }
});

// --- إنشاء حساب المسؤول الافتراضي (إذا لم يكن موجوداً) ---
async function createAdminIfNotExists() {
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@gmail.com';
  const adminPassword = process.env.ADMIN_PASSWORD || 'Mario@1995';
  const existing = await User.findOne({ email: adminEmail });
  if (!existing) {
    const admin = new User({
      name: 'Admin',
      email: adminEmail,
      password: adminPassword,
      isAdmin: true,
      isActive: true
    });
    await admin.save();
    console.log('✅ Admin user created with email:', adminEmail);
  } else {
    console.log('ℹ️ Admin user already exists.');
  }
}

// ============================================================
// 5.  تشغيل الخادم
// ============================================================
const PORT = process.env.PORT || 3001;
app.listen(PORT, async () => {
  console.log(`✅ Server running on port ${PORT}`);
  await createAdminIfNotExists();
});
