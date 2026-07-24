require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// CORS
app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        const allowed = [
            'https://hacene-tv2-0.vercel.app',
            'http://localhost:3000',
            'http://localhost:5500',
            'https://hacenetv2-0.onrender.com',
            'https://hacenetv2-0-ua0u.onrender.com',
            'https://hacenetvstalker.onrender.com'
        ];
        const clean = origin.replace(/\/$/, '');
        if (allowed.includes(clean) || allowed.includes(origin)) {
            callback(null, true);
        } else {
            callback(null, true);
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// MongoDB
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
    console.error('❌ MONGODB_URI not defined');
    process.exit(1);
}

mongoose.connect(MONGODB_URI)
    .then(() => console.log('✅ Connected to MongoDB'))
    .catch(err => {
        console.error('❌ MongoDB connection error:', err);
        process.exit(1);
    });

// ===== Schemas =====
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, trim: true, lowercase: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'user'], default: 'user' },
    isActive: { type: Boolean, default: true },
    xtream: {
        server: { type: String, default: '' },
        username: { type: String, default: '' },
        password: { type: String, default: '' }
    },
    // ===== سجل المشاهدة =====
    history: { type: Array, default: [] }, // [{ channelId, channelName, watchedAt }]
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);

const ChannelSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    channels: { type: Array, default: [] },
    updatedAt: { type: Date, default: Date.now }
});

const Channel = mongoose.model('Channel', ChannelSchema);

// ===== إحصائيات المدير (مخزنة مؤقتاً في الذاكرة أو قاعدة بيانات) =====
// نستخدم نموذجاً لتخزين الإحصائيات
const StatsSchema = new mongoose.Schema({
    totalViews: { type: Number, default: 0 },
    activeUsersToday: { type: Number, default: 0 },
    lastUpdated: { type: Date, default: Date.now }
});
const Stats = mongoose.model('Stats', StatsSchema);

// ===== Helpers =====
function generateToken(userId, email, role) {
    return jwt.sign(
        { userId, email, role },
        process.env.JWT_SECRET || 'hacene_tv_secret_key_2025',
        { expiresIn: '30d' }
    );
}

function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'hacene_tv_secret_key_2025');
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

function adminMiddleware(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin required' });
    }
    next();
}

// ===== Auth endpoints =====
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
        if (password.length < 6) return res.status(400).json({ error: 'Password min 6 chars' });

        const existing = await User.findOne({ email: email.toLowerCase() });
        if (existing) return res.status(400).json({ error: 'Email already registered' });

        const hashed = await bcrypt.hash(password, 10);
        const count = await User.countDocuments();
        const role = count === 0 ? 'admin' : 'user';

        const user = new User({
            email: email.toLowerCase(),
            password: hashed,
            role: role,
            isActive: true,
            xtream: { server: '', username: '', password: '' },
            history: []
        });
        await user.save();

        const token = generateToken(user._id, user.email, user.role);
        res.status(201).json({
            success: true,
            token,
            user: {
                id: user._id,
                email: user.email,
                role: user.role,
                isActive: user.isActive,
                xtream: user.xtream,
                history: user.history
            }
        });
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ error: 'Server error: ' + err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) return res.status(401).json({ error: 'Invalid email or password' });

        if (!user.isActive) return res.status(403).json({ error: 'Account disabled' });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'Invalid email or password' });

        const token = generateToken(user._id, user.email, user.role);
        res.json({
            success: true,
            token,
            user: {
                id: user._id,
                email: user.email,
                role: user.role,
                isActive: user.isActive,
                xtream: user.xtream,
                history: user.history
            }
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error: ' + err.message });
    }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json({ user });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ===== User Xtream & Channels =====
app.post('/api/user/xtream', authMiddleware, async (req, res) => {
    try {
        const { server, username, password } = req.body;
        if (!server || !username || !password) {
            return res.status(400).json({ error: 'All fields required' });
        }
        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        user.xtream = { server, username, password };
        await user.save();
        res.json({ success: true, xtream: user.xtream });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ===== جلب القنوات باستخدام وكيل cors-anywhere =====
const PROXY_URL = process.env.PROXY_URL || 'https://cors-anywhere-tfit.onrender.com';

app.get('/api/user/fetch-channels', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        const { server, username, password } = user.xtream;
        if (!server || !username || !password) {
            return res.status(400).json({ error: 'Xtream not configured' });
        }

        const targetUrl = `${server}/player_api.php?username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}&action=get_live_streams`;
        const proxyUrl = `${PROXY_URL}/${targetUrl}`;

        const response = await fetch(proxyUrl, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Origin': 'https://hacenetv2-0-ua0u.onrender.com',
                'X-Requested-With': 'XMLHttpRequest',
                'Accept': 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status} - ${response.statusText}`);
        }

        const data = await response.json();
        if (!Array.isArray(data)) throw new Error('Invalid response');

        const channels = data.map(item => {
            let streamId = item.stream_id;
            if (streamId && String(streamId).includes('/')) {
                const parts = String(streamId).split('/');
                streamId = parts[parts.length - 1];
            }
            return {
                name: item.name || 'بدون اسم',
                category: item.category_name || 'عام',
                stream_id: streamId,
                icon: item.stream_icon || '',
                url: ''
            };
        });

        await Channel.findOneAndUpdate(
            { userId: user._id },
            { userId: user._id, channels, updatedAt: Date.now() },
            { upsert: true, new: true }
        );

        res.json({ success: true, channels, count: channels.length });
    } catch (err) {
        console.error('Fetch channels error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/user/channels', authMiddleware, async (req, res) => {
    try {
        const doc = await Channel.findOne({ userId: req.user.userId });
        res.json({ channels: doc ? doc.channels : [] });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/user/channels', authMiddleware, async (req, res) => {
    try {
        const { channels } = req.body;
        if (!Array.isArray(channels)) return res.status(400).json({ error: 'Channels must be array' });
        await Channel.findOneAndUpdate(
            { userId: req.user.userId },
            { userId: req.user.userId, channels, updatedAt: Date.now() },
            { upsert: true, new: true }
        );
        res.json({ success: true, channels });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ===== سجل المشاهدة (History) =====
app.post('/api/user/history', authMiddleware, async (req, res) => {
    try {
        const { channelId, channelName } = req.body;
        if (!channelId || !channelName) {
            return res.status(400).json({ error: 'channelId and channelName required' });
        }
        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });

        // إزالة أي سجل مكرر لهذه القناة
        user.history = user.history.filter(item => item.channelId !== channelId);
        // إضافة القناة إلى البداية
        user.history.unshift({
            channelId,
            channelName,
            watchedAt: new Date().toISOString()
        });
        // الاحتفاظ بآخر 50 مشاهدة فقط
        if (user.history.length > 50) user.history = user.history.slice(0, 50);

        await user.save();
        res.json({ success: true, history: user.history });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/user/history', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json({ history: user.history || [] });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ===== إحصائيات المدير =====
app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        // عدد المستخدمين الكلي
        const totalUsers = await User.countDocuments();
        // عدد المستخدمين النشطين اليوم (الذين سجلوا دخول خلال 24 ساعة)
        const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
        const activeUsers = await User.countDocuments({ lastLogin: { $gte: oneDayAgo } });
        // إجمالي القنوات المحفوظة (من جميع المستخدمين)
        const channelsDocs = await Channel.find({});
        let totalChannels = 0;
        channelsDocs.forEach(doc => { totalChannels += doc.channels.length; });
        // عدد مرات تشغيل القنوات (تقريباً)
        const stats = await Stats.findOne();
        const totalViews = stats ? stats.totalViews : 0;

        res.json({
            totalUsers,
            activeUsersToday: activeUsers,
            totalChannels,
            totalViews,
            lastUpdated: stats ? stats.lastUpdated : new Date()
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// تحديث الإحصائيات عند تشغيل قناة (يتم استدعاؤها من الواجهة)
app.post('/api/admin/stats/view', authMiddleware, async (req, res) => {
    try {
        let stats = await Stats.findOne();
        if (!stats) {
            stats = new Stats({ totalViews: 0, activeUsersToday: 0 });
        }
        stats.totalViews += 1;
        // تحديث وقت آخر تحديث
        stats.lastUpdated = new Date();
        await stats.save();

        // تحديث آخر دخول للمستخدم
        await User.findByIdAndUpdate(req.user.userId, { lastLogin: new Date() });

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ===== Admin endpoints =====
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const users = await User.find({}).select('-password');
        res.json({ users });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.put('/api/admin/users/:userId', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { userId } = req.params;
        const { isActive, xtream } = req.body;
        if (userId === req.user.userId) return res.status(403).json({ error: 'Cannot modify self' });

        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });

        if (isActive !== undefined) user.isActive = isActive;
        if (xtream) {
            user.xtream = {
                server: xtream.server || '',
                username: xtream.username || '',
                password: xtream.password || ''
            };
        }
        await user.save();

        res.json({
            success: true,
            user: {
                id: user._id,
                email: user.email,
                role: user.role,
                isActive: user.isActive,
                xtream: user.xtream
            }
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.delete('/api/admin/users/:userId', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { userId } = req.params;
        if (userId === req.user.userId) return res.status(403).json({ error: 'Cannot delete self' });
        await User.findByIdAndDelete(userId);
        await Channel.findOneAndDelete({ userId });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ===== Admin Notification (مع دعم البريد المستهدف) =====
app.post('/api/admin/notifications', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { message, targetEmail } = req.body;
        if (!message) return res.status(400).json({ error: 'Message required' });

        let users = [];
        if (targetEmail) {
            const user = await User.findOne({ email: targetEmail.toLowerCase() });
            if (!user) return res.status(404).json({ error: 'User not found' });
            users = [user];
        } else {
            users = await User.find({});
        }

        // هنا يمكن حفظ الإشعارات في قاعدة بيانات، لكن حالياً نعيد العدد
        res.json({ success: true, count: users.length, message });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ===== Proxy عام (احتياطي) =====
app.get('/api/proxy', async (req, res) => {
    try {
        const target = req.query.url;
        if (!target) return res.status(400).json({ error: 'Missing url' });
        const response = await fetch(target);
        if (!response.ok) return res.status(response.status).json({ error: 'Fetch failed' });
        const data = await response.json();
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: 'Proxy error: ' + err.message });
    }
});

// ===== Health =====
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});
