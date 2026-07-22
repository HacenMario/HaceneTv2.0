require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// ================================================================
// 1.  إعدادات middleware
// ================================================================
app.use(cors({
    origin: process.env.FRONTEND_URL || '*',
    credentials: true
}));
app.use(express.json());

// ================================================================
// 2.  الاتصال بقاعدة البيانات MongoDB
// ================================================================
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
    console.error('❌ MONGODB_URI is not defined in environment variables');
    process.exit(1);
}

mongoose.connect(MONGODB_URI)
    .then(() => console.log('✅ Connected to MongoDB'))
    .catch(err => {
        console.error('❌ MongoDB connection error:', err);
        process.exit(1);
    });

// ================================================================
// 3.  نماذج البيانات (Schemas)
// ================================================================

// 3.1 نموذج المستخدم
const UserSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ['admin', 'user'],
        default: 'user'
    },
    isActive: {
        type: Boolean,
        default: true
    },
    xtream: {
        server: { type: String, default: '' },
        username: { type: String, default: '' },
        password: { type: String, default: '' }
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const User = mongoose.model('User', UserSchema);

// 3.2 نموذج القنوات (لكل مستخدم)
const ChannelSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    channels: {
        type: Array,
        default: []
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

const Channel = mongoose.model('Channel', ChannelSchema);

// ================================================================
// 4.  دوال المساعدة (Helper functions)
// ================================================================

// 4.1 إنشاء token JWT
function generateToken(userId, email, role) {
    return jwt.sign(
        { userId, email, role },
        process.env.JWT_SECRET || 'hacene_tv_secret_key_2025',
        { expiresIn: '30d' }
    );
}

// 4.2 التحقق من صلاحية token (Middleware)
function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized: No token provided' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'hacene_tv_secret_key_2025');
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Unauthorized: Invalid token' });
    }
}

// 4.3 التحقق من صلاحيات Admin
function adminMiddleware(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden: Admin access required' });
    }
    next();
}

// ================================================================
// 5.  نقاط النهاية (API Endpoints)
// ================================================================

// 5.1 تسجيل مستخدم جديد
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password } = req.body;

        // التحقق من صحة الإدخال
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        // التحقق من وجود المستخدم
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        // تشفير كلمة المرور
        const hashedPassword = await bcrypt.hash(password, 10);

        // إنشاء المستخدم
        const user = new User({
            email: email.toLowerCase(),
            password: hashedPassword,
            role: 'user',
            isActive: true,
            xtream: { server: '', username: '', password: '' }
        });

        await user.save();

        // إنشاء token
        const token = generateToken(user._id, user.email, user.role);

        res.status(201).json({
            success: true,
            token,
            user: {
                id: user._id,
                email: user.email,
                role: user.role,
                isActive: user.isActive,
                xtream: user.xtream
            }
        });
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// 5.2 تسجيل الدخول
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // التحقق من أن الحساب نشط
        if (!user.isActive) {
            return res.status(403).json({ error: 'Account is disabled. Contact administrator.' });
        }

        // التحقق من كلمة المرور
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const token = generateToken(user._id, user.email, user.role);

        res.json({
            success: true,
            token,
            user: {
                id: user._id,
                email: user.email,
                role: user.role,
                isActive: user.isActive,
                xtream: user.xtream
            }
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// 5.3 الحصول على بيانات المستخدم الحالي
app.get('/api/auth/me', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ user });
    } catch (err) {
        console.error('Get user error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// 5.4 حفظ بيانات Xtream للمستخدم الحالي
app.post('/api/user/xtream', authMiddleware, async (req, res) => {
    try {
        const { server, username, password } = req.body;
        const userId = req.user.userId;

        if (!server || !username || !password) {
            return res.status(400).json({ error: 'Server, username, and password are required' });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        user.xtream = { server, username, password };
        await user.save();

        res.json({
            success: true,
            message: 'Xtream settings saved successfully',
            xtream: user.xtream
        });
    } catch (err) {
        console.error('Save Xtream error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// 5.5 جلب القنوات من Xtream (للمستخدم الحالي)
app.get('/api/user/fetch-channels', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const { server, username, password } = user.xtream;
        if (!server || !username || !password) {
            return res.status(400).json({ error: 'Xtream credentials not configured' });
        }

        // جلب القنوات من خادم Xtream
        const url = `${server}/player_api.php?username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}&action=get_live_streams`;
        const proxy = 'https://hacene-iptv.onrender.com/api?url=';
        const finalUrl = proxy + encodeURIComponent(url);

        const response = await fetch(finalUrl);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const data = await response.json();

        if (!Array.isArray(data)) {
            throw new Error('Invalid response from Xtream server');
        }

        // تحويل البيانات إلى صيغة موحدة
        const channels = data.map(item => ({
            name: item.name || 'بدون اسم',
            category: item.category_name || 'عام',
            stream_id: item.stream_id,
            icon: item.stream_icon || '',
            url: ''
        }));

        // حفظ القنوات في قاعدة البيانات
        await Channel.findOneAndUpdate(
            { userId: user._id },
            { userId: user._id, channels, updatedAt: Date.now() },
            { upsert: true, new: true }
        );

        res.json({
            success: true,
            channels: channels,
            count: channels.length
        });
    } catch (err) {
        console.error('Fetch channels error:', err);
        res.status(500).json({ error: err.message || 'Failed to fetch channels' });
    }
});

// 5.6 الحصول على قنوات المستخدم المحفوظة
app.get('/api/user/channels', authMiddleware, async (req, res) => {
    try {
        const channelDoc = await Channel.findOne({ userId: req.user.userId });
        if (!channelDoc) {
            return res.json({ channels: [] });
        }
        res.json({ channels: channelDoc.channels });
    } catch (err) {
        console.error('Get channels error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// 5.7 حفظ قنوات المستخدم (للمزامنة)
app.post('/api/user/channels', authMiddleware, async (req, res) => {
    try {
        const { channels } = req.body;
        if (!Array.isArray(channels)) {
            return res.status(400).json({ error: 'Channels must be an array' });
        }

        await Channel.findOneAndUpdate(
            { userId: req.user.userId },
            { userId: req.user.userId, channels, updatedAt: Date.now() },
            { upsert: true, new: true }
        );

        res.json({ success: true, channels });
    } catch (err) {
        console.error('Save channels error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ================================================================
// 6.  نقاط النهاية الخاصة بـ Admin
// ================================================================

// 6.1 الحصول على جميع المستخدمين (للـ Admin فقط)
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const users = await User.find({}).select('-password');
        res.json({ users });
    } catch (err) {
        console.error('Admin get users error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// 6.2 تحديث مستخدم (للـ Admin فقط)
app.put('/api/admin/users/:userId', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { userId } = req.params;
        const { isActive, xtream, role } = req.body;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // لا يمكن تعديل Admin نفسه أو تغيير دور Admin
        if (userId === req.user.userId) {
            return res.status(403).json({ error: 'Cannot modify your own account' });
        }

        if (isActive !== undefined) user.isActive = isActive;
        if (role && role === 'admin') {
            return res.status(403).json({ error: 'Cannot assign admin role' });
        }
        if (xtream) {
            user.xtream = {
                server: xtream.server || user.xtream.server || '',
                username: xtream.username || user.xtream.username || '',
                password: xtream.password || user.xtream.password || ''
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
        console.error('Admin update user error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// 6.3 حذف مستخدم (للـ Admin فقط)
app.delete('/api/admin/users/:userId', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { userId } = req.params;

        if (userId === req.user.userId) {
            return res.status(403).json({ error: 'Cannot delete your own account' });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // حذف قنوات المستخدم
        await Channel.findOneAndDelete({ userId });
        // حذف المستخدم
        await User.findByIdAndDelete(userId);

        res.json({ success: true, message: 'User deleted successfully' });
    } catch (err) {
        console.error('Admin delete user error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ================================================================
// 7.  نقطة نهاية الـ Proxy (لجلب القنوات من Xtream)
// ================================================================
app.get('/api/proxy', async (req, res) => {
    try {
        const targetUrl = req.query.url;
        if (!targetUrl) {
            return res.status(400).json({ error: 'Missing url parameter' });
        }

        const response = await fetch(targetUrl);
        if (!response.ok) {
            return res.status(response.status).json({ error: 'Failed to fetch' });
        }

        const data = await response.json();
        res.json(data);
    } catch (err) {
        console.error('Proxy error:', err);
        res.status(500).json({ error: 'Proxy error' });
    }
});

// ================================================================
// 8.  نقطة نهاية اختبار الصحة
// ================================================================
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
});

// ================================================================
// 9.  تشغيل الخادم
// ================================================================
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`📡 API URL: http://localhost:${PORT}/api`);
});
