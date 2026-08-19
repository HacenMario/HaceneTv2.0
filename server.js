require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');

const app = express();

// CORS
app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        const allowed = [
            'https://hacenetv20-production.up.railway.app',
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

app.get('/', (req, res) => {
  res.json({
    status: 'online',
    message: '🚀 HACENE TV API is running',
    timestamp: new Date().toISOString(),
  });
});

// ✅ Health check endpoint (ضروري لـ Railway)
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
});

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

// ===== JWT Secret =====
const JWT_SECRET = process.env.JWT_SECRET || 'hacene_tv_secret_key_2025';
console.log(`🔑 JWT_SECRET is ${JWT_SECRET === 'hacene_tv_secret_key_2025' ? 'using default' : 'set from environment'}`);

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
    history: { type: Array, default: [] },
    createdAt: { type: Date, default: Date.now },
    lastLogin: { type: Date }
});

const User = mongoose.model('User', UserSchema);

const ChannelSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    channels: { type: Array, default: [] },
    updatedAt: { type: Date, default: Date.now }
});
const Channel = mongoose.model('Channel', ChannelSchema);

const StatsSchema = new mongoose.Schema({
    totalViews: { type: Number, default: 0 },
    activeUsersToday: { type: Number, default: 0 },
    lastUpdated: { type: Date, default: Date.now }
});
const Stats = mongoose.model('Stats', StatsSchema);

const NotificationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    message: { type: String, required: true },
    read: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});
const Notification = mongoose.model('Notification', NotificationSchema);

// ===== Helpers =====
function generateToken(userId, email, role) {
    return jwt.sign(
        { userId, email, role },
        JWT_SECRET,
        { expiresIn: '30d' }
    );
}

// ===== Auth Middleware =====
function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    console.log(`🔍 Auth header received: ${authHeader ? 'Yes' : 'No'}`);
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.log('❌ No Bearer token found in headers');
        return res.status(401).json({ 
            error: 'Unauthorized',
            message: 'No token provided'
        });
    }
    
    const token = authHeader.split(' ')[1];
    console.log(`🔑 Token received (first 20 chars): ${token.substring(0, 20)}...`);
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        console.log(`✅ User authenticated: ${decoded.email} (${decoded.role})`);
        next();
    } catch (err) {
        console.log(`❌ Token verification failed: ${err.message}`);
        return res.status(401).json({ 
            error: 'Unauthorized',
            message: 'Invalid or expired token'
        });
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

        user.lastLogin = new Date();
        await user.save();

        const token = generateToken(user._id, user.email, user.role);
        console.log(`✅ Login successful for ${user.email}, token generated`);
        
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

// ===== اختبار صلاحية التوكن =====
app.get('/api/auth/verify', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ 
            valid: true, 
            user: {
                id: user._id,
                email: user.email,
                role: user.role
            }
        });
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

// ===== وكيل مدمج =====
app.get('/api/proxy/fetch', authMiddleware, async (req, res) => {
    try {
        const targetUrl = req.query.url;
        if (!targetUrl) {
            return res.status(400).json({ error: 'URL parameter required' });
        }

        if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
            return res.status(400).json({ error: 'Invalid URL format' });
        }

        const response = await fetch(targetUrl, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        res.json(data);
    } catch (err) {
        console.error('Proxy error:', err);
        res.status(500).json({ error: 'Proxy error: ' + err.message });
    }
});

// ===== جلب القنوات باستخدام الوكيل المدمج =====
app.get('/api/user/fetch-channels', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const { server, username, password } = user.xtream;
        if (!server || !username || !password) {
            return res.status(400).json({ error: 'Xtream not configured' });
        }

        if (!server.startsWith('http://') && !server.startsWith('https://')) {
            return res.status(400).json({ error: 'Invalid server URL' });
        }

        const targetUrl = `${server}/player_api.php?username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}&action=get_live_streams`;
        const proxyUrl = `${req.protocol}://${req.get('host')}/api/proxy/fetch?url=${encodeURIComponent(targetUrl)}`;
        
        console.log(`📡 Fetching channels via proxy: ${proxyUrl}`);
        
        const response = await fetch(proxyUrl);
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || `HTTP ${response.status}`);
        }
        
        const data = await response.json();
        
        if (!Array.isArray(data)) {
            throw new Error('Invalid response format');
        }

        const channels = data.map(item => ({
            name: item.name || 'بدون اسم',
            category: item.category_name || 'عام',
            stream_id: item.stream_id || '',
            icon: item.stream_icon || '',
            url: ''
        }));

        await Channel.findOneAndUpdate(
            { userId: user._id },
            { userId: user._id, channels, updatedAt: Date.now() },
            { upsert: true, new: true }
        );

        res.json({ success: true, channels, count: channels.length });
    } catch (err) {
        console.error('Fetch channels error:', err);
        res.status(500).json({ 
            error: err.message,
            details: 'Failed to fetch channels. Please check your Xtream credentials or try again later.'
        });
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

app.post('/api/user/history', authMiddleware, async (req, res) => {
    try {
        const { channelId, channelName } = req.body;
        if (!channelId || !channelName) {
            return res.status(400).json({ error: 'channelId and channelName required' });
        }
        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });

        user.history = user.history.filter(item => item.channelId !== channelId);
        user.history.unshift({
            channelId,
            channelName,
            watchedAt: new Date().toISOString()
        });
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

app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
        const activeUsers = await User.countDocuments({ lastLogin: { $gte: oneDayAgo } });
        const channelsDocs = await Channel.find({});
        let totalChannels = 0;
        channelsDocs.forEach(doc => { totalChannels += doc.channels.length; });
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

app.post('/api/admin/stats/view', authMiddleware, async (req, res) => {
    try {
        let stats = await Stats.findOne();
        if (!stats) {
            stats = new Stats({ totalViews: 0, activeUsersToday: 0 });
        }
        stats.totalViews += 1;
        stats.lastUpdated = new Date();
        await stats.save();

        await User.findByIdAndUpdate(req.user.userId, { lastLogin: new Date() });

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

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
        await Notification.deleteMany({ userId });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ===== نظام الإشعارات =====
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

        const notifications = users.map(user => ({
            userId: user._id,
            message: message,
            read: false,
            createdAt: new Date()
        }));

        if (notifications.length > 0) {
            await Notification.insertMany(notifications);
        }

        res.json({
            success: true,
            count: notifications.length,
            message: `✅ تم إرسال الإشعار إلى ${notifications.length} مستخدم`
        });
    } catch (err) {
        console.error('Error sending notification:', err);
        res.status(500).json({ error: 'Server error: ' + err.message });
    }
});

app.get('/api/user/notifications', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.userId;
        const notifications = await Notification.find({ userId })
            .sort({ createdAt: -1 })
            .limit(100);
        res.json({ notifications });
    } catch (err) {
        console.error('Error fetching notifications:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.put('/api/user/notifications/:id/read', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.user.userId;

        const notification = await Notification.findOne({ _id: id, userId });
        if (!notification) {
            return res.status(404).json({ error: 'Notification not found' });
        }

        notification.read = true;
        await notification.save();

        res.json({ success: true, notification });
    } catch (err) {
        console.error('Error marking notification as read:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.delete('/api/user/notifications/read', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.userId;
        await Notification.deleteMany({ userId, read: true });
        res.json({ success: true, message: 'تم حذف الإشعارات المقروءة' });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ===== Proxy عام =====
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

// ===== بدء الخادم مع معالجة الإشارات والأخطاء =====
const PORT = process.env.PORT || 3001;

const server = app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`🌐 API Base URL: ${process.env.API_BASE || `hacenetv20-production.up.railway.app:${PORT}`}`);
});

console.log('🚀 Server is ready to accept requests.');

// منع الخروج بسبب أخطاء غير معالجة
process.on('uncaughtException', (err) => {
    console.error('💥 Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
});

// استقبال SIGTERM بشكل آمن
process.on('SIGTERM', () => {
    console.log('🛑 SIGTERM received, closing gracefully...');
    server.close(() => {
        console.log('✅ Server closed');
        mongoose.connection.close(false, () => {
            console.log('✅ MongoDB connection closed');
            process.exit(0);
        });
    });
});

// استقبال SIGINT (Ctrl+C)
process.on('SIGINT', () => {
    console.log('🛑 SIGINT received, closing gracefully...');
    server.close(() => {
        console.log('✅ Server closed');
        mongoose.connection.close(false, () => {
            console.log('✅ MongoDB connection closed');
            process.exit(0);
        });
    });
});
